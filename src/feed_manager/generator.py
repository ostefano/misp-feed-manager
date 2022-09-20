import abc
import collections

import uuid
import pymisp
import hashlib
import os
import json
import datetime
import logging

from typing import Dict
from typing import Optional
from typing import Tuple


FeedProperties = collections.namedtuple("FeedProperties", [
    "tag",
    "analysis",
    "threat_level_id",
    "published",
    "organization_name",
    "organization_uuid",
])


class AbstractFeedGenerator(abc.ABC):
    """Abstract class for every feed generators."""

    DATETIME_FMT = "%Y-%m-%d %H:%M:%S"

    DEFAULT_FEED_PROPERTIES = FeedProperties(
        tag=[
            {
                "colour": "#ffffff",
                "name": "tlp:white"
            },
        ],
        analysis=0,
        threat_level_id=1,
        published=False,
        organization_name="Default organization",
        organization_uuid=str(uuid.uuid4()),
    )

    def __init__(self, output_dir):
        """Constructor."""
        self._logger = logging.getLogger(__name__)
        self._output_dir = output_dir
        self._attribute_hashes = []
        self._manifest = {}

    @staticmethod
    def attribute_equals(attr1: pymisp.MISPAttribute, attr2: pymisp.MISPAttribute) -> bool:
        """Return whether two attributes are the same."""
        return (
            attr1.type == attr2.type and
            attr1.value == attr2.value and
            attr1.data == attr2.data
        )

    @classmethod
    def object_equals(cls, obj1: pymisp.MISPObject, obj2: pymisp.MISPObject) -> bool:
        """Return whether two objects are the same."""
        obj1_attributes = sorted(obj1.attributes, key=lambda x: x.type)
        obj2_attributes = sorted(obj2.attributes, key=lambda x: x.type)
        if len(obj1_attributes) != len(obj2_attributes):
            return False
        for attr1, attr2 in zip(obj1_attributes, obj2_attributes):
            if not cls.attribute_equals(attr1, attr2):
                return False
        return True

    @classmethod
    def contains_attribute(
        cls,
        misp_event: pymisp.MISPEvent,
        attr_type: str,
        attr_value: str,
        **attr_data,
    ) -> bool:
        """Return whether the misp event contains a specific attribute."""
        fake_attribute = pymisp.MISPAttribute()
        fake_attribute.from_dict(
            type=attr_type,
            value=attr_value,
            data=attr_data,
        )
        for attr in misp_event.attributes:
            if cls.attribute_equals(fake_attribute, attr):
                return True
        return False

    @classmethod
    def contains_object(cls, misp_event: pymisp.MISPEvent, misp_object: pymisp.MISPObject) -> bool:
        """Return whether the misp event contains a specific object."""
        for obj in misp_event.objects:
            if cls.object_equals(obj, misp_object):
                return True
        return False

    @abc.abstractmethod
    def add_object_to_event(self, misp_object: pymisp.MISPObject) -> bool:
        """Add object to the current event."""

    @abc.abstractmethod
    def add_attribute_to_event(self, attr_type: str, attr_value: str, **attr_data) -> bool:
        """Add an attribute to the current event."""

    @abc.abstractmethod
    def flush_event(self, event: Optional[pymisp.MISPEvent] = None) -> None:
        """Flush the current event (if not specified)."""

    def _load_event(self, event_uuid: str) -> pymisp.MISPEvent:
        """Load an event give its uuid."""
        with open(os.path.join(self._output_dir, f"{event_uuid}.json"), "r") as f:
            event_dict = json.load(f)["Event"]
            event = pymisp.MISPEvent()
            event.from_dict(**event_dict)
            return event

    def _save_manifest(self) -> None:
        """Save the manifest to disk."""
        with open(os.path.join(self._output_dir, "manifest.json"), "w") as manifest_file:
            json.dump(self._manifest, manifest_file, indent=True)
        self._logger.debug("Manifest saved")

    def _load_manifest(self) -> Dict[str, Dict]:
        """Load the manifest."""
        manifest_path = os.path.join(self._output_dir, "manifest.json")
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
        return manifest

    def _add_hash(self, event: pymisp.MISPEvent, attr_type: str, attr_value: str) -> None:
        """Take the attribute properties and add a hash."""
        _ = attr_type
        for frag in attr_value.split("|"):
            frag_hash = hashlib.md5(str(frag).encode("utf-8"), usedforsecurity=False).hexdigest()
            self._attribute_hashes.append([frag_hash, event.get("uuid")])

    def _save_hashes(self) -> None:
        """Save the collected hashes to disk."""
        with open(os.path.join(self._output_dir, "hashes.csv"), "a") as hash_file:
            for element in self._attribute_hashes:
                hash_file.write(f"{element[0]},{element[1]}\n")
        self._logger.debug("Hashes saved")
        self._attribute_hashes.clear()


class PeriodicFeedGenerator(AbstractFeedGenerator, abc.ABC):
    """A periodic feed generator that needs to be specialized further."""

    @classmethod
    @abc.abstractmethod
    def get_bucket(cls, date_obj: datetime.datetime) -> str:
        """Return the periodic bucket given the provided date object."""

    @classmethod
    def get_bucket_from_date_str(cls, event_date_str: str) -> str:
        """Get the bucket from the given date string."""
        date_obj = datetime.datetime.strptime(event_date_str, cls.DATETIME_FMT)
        return cls.get_bucket(date_obj)

    @classmethod
    def get_current_bucket(cls) -> str:
        """Get the current bucket (truncated datetime object)."""
        return cls.get_bucket(datetime.datetime.utcnow())

    def __init__(
        self,
        output_dir: str,
        feed_title: str,
        feed_properties: Optional[FeedProperties] = None,
    ):
        """Constructor."""
        super(PeriodicFeedGenerator, self).__init__(output_dir)
        self._feed_properties = feed_properties or self.DEFAULT_FEED_PROPERTIES
        self._feed_title = feed_title
        try:
            self._manifest = self._load_manifest()
        except FileNotFoundError:
            self._logger.debug("Manifest not found, generating a new one")
            self._manifest = {}
            new_event = self._create_event(self.get_current_bucket())
            # flush new event for the first time and manifest
            self.flush_event(event=new_event)
            self._manifest.update(new_event.manifest)
            self._save_manifest()

        event_uuid, event_date_str = self._get_last_event_metadata()
        self._current_event_bucket = self.get_bucket_from_date_str(event_date_str)
        self._current_event = self._load_event(event_uuid)

    def add_object_to_event(self, misp_object: pymisp.MISPObject) -> bool:
        """Implement interface."""
        self._update_event_bucket()
        if self.contains_object(self._current_event, misp_object):
            return False
        self._current_event.add_object(misp_object)
        for attribute in misp_object.attributes:
            self._add_hash(self._current_event, attribute.type, attribute.value)
        return True

    def add_attribute_to_event(self, attr_type: str, attr_value: str, **attr_data) -> bool:
        """Implement interface."""
        self._update_event_bucket()
        if self.contains_attribute(self._current_event, attr_type, attr_value, **attr_data):
            return False
        self._current_event.add_attribute(attr_type, attr_value, **attr_data)
        self._add_hash(self._current_event, attr_type, attr_value)
        return True

    def flush_event(self, event: Optional[pymisp.MISPEvent] = None) -> None:
        """Implement interface."""
        if not event:
            event = self._current_event
        with open(os.path.join(self._output_dir, event.get("uuid") + ".json"), "w") as event_file:
            json.dump(event.to_feed(), event_file, indent=True)
        self._save_hashes()

    def _update_event_bucket(self) -> None:
        """Update the current bucket if needed."""
        event_bucket = self.get_current_bucket()
        if self._current_event_bucket != event_bucket:
            self._logger.debug(
                "New event bucket required (new=%s, old=%s)",
                event_bucket, self._current_event_bucket,
            )
            # flush previous event
            self.flush_event()
            # create new event
            self._current_event_bucket = event_bucket
            self._current_event = self._create_event(event_bucket)
            # flush new event for the first time and manifest
            self.flush_event()
            self._manifest.update(self._current_event.manifest)
            self._save_manifest()

    def _get_last_event_metadata(self) -> Tuple[str, str]:
        """Get the metadata related to the latest event."""
        dated_events = []
        for event_uuid, event_json in self._manifest.items():
            dated_events.append((
                event_json["date"],
                event_uuid,
                event_json["info"],
            ))
        # Sort by date then by event name
        dated_events.sort(key=lambda k: (k[0], k[2], k[1]), reverse=True)
        return dated_events[0][1], dated_events[0][0]

    def _create_event(self, event_bucket: str) -> pymisp.MISPEvent:
        """Create an even in the given bucket."""
        event = pymisp.MISPEvent()
        event.from_dict(**{
            'id': len(self._manifest) + 1,
            'info': f"{self._feed_title} ({event_bucket})",
            'date': datetime.datetime.utcnow().strftime(self.DATETIME_FMT),
            "analysis": self._feed_properties.analysis,
            "threat_level_id": self._feed_properties.threat_level_id,
            "published": self._feed_properties.published,
            "Tag": self._feed_properties.tag,
        })
        org = pymisp.MISPOrganisation()
        org.name = self._feed_properties.organization_name
        org.uuid = self._feed_properties.organization_uuid
        event.Orgc = org
        return event


class DailyFeedGenerator(PeriodicFeedGenerator):
    """A feed generator that creates a different event every day."""

    @classmethod
    def get_bucket(cls, date_obj: datetime.datetime) -> str:
        """Implement interface."""
        return date_obj.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        ).strftime(cls.DATETIME_FMT)

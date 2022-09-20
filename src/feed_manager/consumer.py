import abc
import datetime
import json
import os
import requests


from typing import List, Dict


class AbstractFeedConsumer(abc.ABC):
    """Abstract implementation of a consumer."""

    DEFAULT_FMT = "%Y-%m-%d %H:%M:%S"

    @abc.abstractmethod
    def load_manifest(self) -> Dict:
        """Return the manifest as a dictionary."""

    @abc.abstractmethod
    def load_event(self, event_uuid) -> Dict:
        """Load the event as a dictionary"""

    @staticmethod
    def _timestamp_to_date_str(timestamp: float, fmt: str = None) -> str:
        date_object = datetime.datetime.fromtimestamp(int(timestamp))
        return date_object.strftime(fmt or AbstractFeedConsumer.DEFAULT_FMT)

    def _get_event_uuids_since(self, since_timestamp: float = None) -> List[str]:
        event_uuids = []
        for event_uuid, event_data in self.load_manifest().items():
            if not since_timestamp or event_data["timestamp"] > since_timestamp:
                event_uuids.append(event_uuid)
        return event_uuids

    def _get_events_since(self, date_object: datetime.datetime) -> Dict[str, Dict]:
        event_uuids = self._get_event_uuids_since(date_object.timestamp())
        event_data_by_uuid = {}
        for event_uuid in event_uuids:
            event_data_by_uuid[event_uuid] = self.load_event(event_uuid)
        return event_data_by_uuid

    def get_indicators_since(self, date_object: datetime.datetime, indicator_type: str) -> List[Dict]:
        ret = []
        for event_uuid, event_data in self._get_events_since(date_object).items():
            for obj in event_data["Event"]["Object"]:
                for attribute in obj["Attribute"]:
                    if indicator_type == attribute["type"]:
                        ret.append({
                            "timestamp": self._timestamp_to_date_str(event_data["Event"]["timestamp"]),
                            "event_uuid": event_uuid,
                            "object_uuid": obj["uuid"],
                            "attribute_uuid": attribute["uuid"],
                            "indicator": attribute["value"],
                            "tags": [x["name"] for x in attribute["Tag"]],
                        })
        return ret


class LocalFeedConsumer(AbstractFeedConsumer):
    """Consumer using a local directory."""

    def load_manifest(self) -> Dict:
        with open(os.path.join(self._input_dir, "manifest.json"), "r") as f:
            return json.load(f)

    def load_event(self, event_uuid: str) -> Dict:
        with open(os.path.join(self._input_dir, f"{event_uuid}.json"), "r") as f:
            return json.load(f)

    def __init__(self, input_dir: str):
        self._input_dir = input_dir


class RemoteFeedConsumer(AbstractFeedConsumer):
    """Consumer using a remote (HTTP) source."""

    def load_manifest(self) -> Dict:
        ret = requests.get(f"{self._base_url}/manifest.json")
        return ret.json()

    def load_event(self, event_uuid: str) -> Dict:
        ret = requests.get(f"{self._base_url}/{event_uuid}.json")
        return ret.json()

    def __init__(self, base_url: str):
        self._base_url = base_url.rstrip("/")

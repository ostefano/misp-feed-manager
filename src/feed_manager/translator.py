import feed_manager

from typing import List
from typing import Optional
from typing import Tuple
from typing import Union


try:
    import pymisp
except ImportError as ie:
    pymisp = None
    feed_manager.print_dependency_error_and_raise(ie)


class TagUtils:
    """Class with utility methods to handle tags."""

    # map object name to the attribute used to store object tags
    OBJECT_NAME_TO_ATTRIBUTE_TAG = {
        "file": "filename",
        "network-profile": "text",
        "sandbox-report": "score",
        "atp-report": "score",
    }

    @classmethod
    def __workaround_bug(cls, object_attribute: pymisp.MISPAttribute) -> pymisp.MISPAttribute:
        """Workaround the current pymisp bug where object attributes have mis-initialized tags."""
        if object_attribute.tags:
            return object_attribute
        if not hasattr(object_attribute, "AttributeTag"):
            return object_attribute
        tags = []
        try:
            for attribute_tag in object_attribute.AttributeTag:
                tag = attribute_tag["Tag"]
                tag_object = pymisp.MISPTag()
                tag_object.from_dict(**tag)
                tags.append(tag_object)
        except KeyError:
            pass
        object_attribute.tags = tags
        return object_attribute

    @classmethod
    def get_taggable_entity(
        cls,
        entity: Union[pymisp.MISPEvent, pymisp.MISPObject, pymisp.MISPAttribute],
    ) -> Union[pymisp.MISPEvent, pymisp.MISPAttribute]:
        """Get the taggable entity."""
        if isinstance(entity, pymisp.MISPEvent):
            return entity
        elif isinstance(entity, pymisp.MISPAttribute):
            return entity
        else:
            try:
                attribute_type = cls.OBJECT_NAME_TO_ATTRIBUTE_TAG[entity.name]
            except KeyError:
                raise ValueError(f"Can not process object '{entity.name}/{entity.uuid}'")
            try:
                return cls.__workaround_bug(entity.get_attributes_by_relation(attribute_type)[0])
            except IndexError:
                raise ValueError(f"Object '{entity.name}/{entity.uuid}' seems malformed'")

    @classmethod
    def validate_tag(cls, input_object: Union[pymisp.MISPTag, str]) -> pymisp.MISPTag:
        """Validate a tag (whether an object or a string) and return an object."""
        if isinstance(input_object, pymisp.MISPTag):
            return input_object
        else:
            return cls.create_tag(name=input_object)

    @classmethod
    def create_tag(cls, name: str, colour: Optional[str] = None) -> pymisp.MISPTag:
        """Create a tag."""
        tag = pymisp.MISPTag()
        tag.from_dict(
            name=name,
            colour=colour,
        )
        return tag

    @classmethod
    def add_tag_to_object(cls, obj: pymisp.MISPObject, tag: Union[str, pymisp.MISPTag]):
        """Add a tag to an object by choosing a representative attribute."""
        attribute = cls.get_taggable_entity(obj)
        cls.add_tag_to_attribute(attribute, tag)

    @classmethod
    def add_tag_to_attribute(cls, attribute: pymisp.MISPAttribute, tag: Union[str, pymisp.MISPTag]):
        """Add a tag to an attribute."""
        tag = cls.validate_tag(tag)
        attribute.add_tag(tag)

    @classmethod
    def entity_contains_tag(
        cls,
        entity: Union[pymisp.MISPEvent, pymisp.MISPObject, pymisp.MISPAttribute],
        tag_name: str,
    ) -> bool:
        """Whether an entity is tagged with a given tag."""
        entity = cls.get_taggable_entity(entity)
        return any(tag.name == tag_name for tag in entity.tags)

    @classmethod
    def entity_contains_any_tags(
        cls,
        entity: Union[pymisp.MISPEvent, pymisp.MISPObject, pymisp.MISPAttribute],
        tag_names: List[str],
    ) -> bool:
        """Whether an entity is tagged with any of the given tags."""
        return any(cls.entity_contains_tag(entity, tag_name) for tag_name in tag_names)

    @classmethod
    def decode_cluster_tag(
        cls,
        tag: Union[str, pymisp.MISPTag],
    ) -> Tuple[Optional[str], Optional[str]]:
        """Decode a galaxy cluster tag into category and value."""
        if isinstance(tag, pymisp.MISPTag):
            tag = tag.name
        try:
            category, value = tag.split("=")
            return category, value.strip("\"")
        except (KeyError, IndexError, ValueError):
            return None, None

    @classmethod
    def get_cluster_tag_value(
        cls,
        tag: Union[str, pymisp.MISPTag],
        category: str = None,
    ) -> Optional[str]:
        """Get the value of a galaxy cluster tag optionally filtering by category."""
        tag_category, tag_value = cls.decode_cluster_tag(tag)
        if category and tag_category:
            return tag_value if tag_category.startswith(category) else None
        else:
            return tag_value


class IndicatorTranslator:
    """Class that translate indicators or telemetry events to MISP objects."""

    DEFAULT_FILE_ATTRIBUTE_CATEGORY = "Payload delivery"
    DEFAULT_NET_ATTRIBUTE_CATEGORY = "Network activity"
    DEFAULT_FILE_NAME = "unknown"
    DEFAULT_WHOIS_ENTRY = "missing"

    @classmethod
    def to_network_attribute(
        cls,
        network_indicator: str,
        tags: Optional[List[Union[str, pymisp.MISPTag]]] = None,
    ) -> pymisp.MISPAttribute:
        """Get a network indicator as attribute."""
        if "://" in network_indicator:
            attribute_type = "url"
        elif len(network_indicator.split(".")) == 4:
            if ":" in network_indicator:
                attribute_type = "ip-dst|port"
            else:
                attribute_type = "ip"
        else:
            attribute_type = "domain"
        net_attribute = pymisp.MISPAttribute()
        net_attribute.from_dict(
            type=attribute_type,
            category=cls.DEFAULT_NET_ATTRIBUTE_CATEGORY,
            value=network_indicator,
        )
        for tag in tags or []:
            TagUtils.add_tag_to_attribute(net_attribute, tag)
        return net_attribute

    @classmethod
    def to_file_attribute(
        cls,
        file_hash,
        attribute_category: str = DEFAULT_FILE_ATTRIBUTE_CATEGORY,
        tags: Optional[List[Union[str, pymisp.MISPTag]]] = None,
    ) -> pymisp.MISPAttribute:
        """Get a file attribute (useful when only a single hash is available)."""
        attribute_type = feed_manager.get_hash_type(file_hash)
        if not attribute_type:
            raise ValueError(f"Invalid hash '{file_hash}'")
        file_attribute = pymisp.MISPAttribute()
        file_attribute.from_dict(
            type=attribute_type,
            category=attribute_category,
            value=file_hash,
        )
        for tag in tags or []:
            TagUtils.add_tag_to_attribute(file_attribute, tag)
        return file_attribute

    @classmethod
    def to_file_object(
        cls,
        file_md5: str,
        file_sha1: str,
        file_sha256: str,
        file_name: Optional[str] = None,
        size: Optional[int] = None,
        mime_type: Optional[str] = None,
        comment: Optional[str] = None,
        attribute_category: str = DEFAULT_FILE_ATTRIBUTE_CATEGORY,
        tags: Optional[List[Union[str, pymisp.MISPTag]]] = None,
    ) -> pymisp.MISPObject:
        """Get a file object (mandatory when having multiple hashes)."""
        file_object = pymisp.MISPObject(name="file")
        file_object.add_attribute(
            "filename",
            value=file_name or cls.DEFAULT_FILE_NAME,
            comment=comment,
            to_ids=False,
        )
        if file_md5:
            file_object.add_attribute(
                "md5",
                value=file_md5,
                category=attribute_category,
                to_ids=True,
            )
        if file_sha1:
            file_object.add_attribute(
                "sha1",
                value=file_sha1,
                category=attribute_category,
                to_ids=True,
            )
        if file_sha256:
            file_object.add_attribute(
                "sha256",
                value=file_sha256,
                category=attribute_category,
                to_ids=True,
            )
        if size:
            file_object.add_attribute(
                "size-in-bytes",
                value=size,
                to_ids=False,
            )
        if mime_type:
            file_object.add_attribute(
                "mimetype",
                value=mime_type,
                to_ids=False,
            )
        for tag in tags or []:
            TagUtils.add_tag_to_object(file_object, tag)
        return file_object

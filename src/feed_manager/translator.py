import itertools
import feed_manager

from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Union


try:
    import pymisp
except ImportError as ie:
    pymisp = None
    feed_manager.print_dependency_error_and_raise(ie)


class TagUtils:
    """Class with utility methods to handle tags."""

    OBJECT_NAME_TO_ATTRIBUTE_TAG = {
        "file": "filename",
        "network-profile": "text",
    }

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
        tag.from_dict(**{
            "name": name,
            "colour": colour,
        })
        return tag

    @classmethod
    def add_tag_to_object(cls, obj: pymisp.MISPObject, tag: Union[str, pymisp.MISPTag]):
        """Add a tag to an object by choosing a representative attribute."""
        try:
            attribute_type = cls.OBJECT_NAME_TO_ATTRIBUTE_TAG[obj.name]
        except KeyError:
            raise ValueError(f"Can not process object '{obj.name}'")
        attribute = obj.get_attributes_by_relation(attribute_type)[0]
        cls.add_tag_to_attribute(attribute, tag)

    @classmethod
    def add_tag_to_attribute(cls, attribute: pymisp.MISPAttribute, tag: Union[str, pymisp.MISPTag]):
        """Add a tag to an attribute."""
        tag = cls.validate_tag(tag)
        attribute.add_tag(tag)


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
    def to_network_object(
        cls,
        domain: Optional[str] = None,
        url: Optional[str] = None,
        ip_address: Optional[str] = None,
        whois_entry: str = DEFAULT_WHOIS_ENTRY,
        tags: Optional[List[Union[str, pymisp.MISPTag]]] = None,
    ) -> pymisp.MISPObject:
        """Get a network indicator as object when multiple indicators are available."""
        if not domain and not url and not ip_address:
            raise ValueError("Invalid network object with no domain url or ip")
        network_obj = pymisp.MISPObject("network-profile")
        network_obj.add_attribute(
            "text",
            value=whois_entry,
            comment="tags assigned to this attribute apply to the whole object",
        )
        if domain:
            network_obj.add_attribute("domain", domain)
        if url:
            network_obj.add_attribute("url", url)
        if ip_address:
            network_obj.add_attribute("ip-address", ip_address)
        for tag in tags or []:
            TagUtils.add_tag_to_object(network_obj, tag)
        return network_obj

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
        attribute_category: str = DEFAULT_FILE_ATTRIBUTE_CATEGORY,
        tags: Optional[List[Union[str, pymisp.MISPTag]]] = None,
    ) -> pymisp.MISPObject:
        """Get a file object (mandatory when having multiple hashes)."""
        file_object = pymisp.MISPObject(name="file")
        file_object.add_attribute(
            "filename",
            value=file_name or cls.DEFAULT_FILE_NAME,
            comment="tags assigned to this attribute apply to the whole object",
        )
        if file_md5:
            file_object.add_attribute(
                "md5",
                value=file_md5,
                category=attribute_category,
            )
        if file_sha1:
            file_object.add_attribute(
                "sha1",
                value=file_sha1,
                category=attribute_category,
            )
        if file_sha256:
            file_object.add_attribute(
                "sha256",
                value=file_sha256,
                category=attribute_category,
            )
        if size:
            file_object.add_attribute(
                "size-in-bytes",
                value=size,
            )
        if mime_type:
            file_object.add_attribute(
                "mimetype",
                value=mime_type,
            )
        for tag in tags or []:
            TagUtils.add_tag_to_object(file_object, tag)
        return file_object

    @classmethod
    def from_contexa_to_objects(
        cls,
        item: Dict[str, Any],
        mitre_attack_galaxy_cluster: Optional[Dict] = None,
        include_sandbox_result: bool = True,
        include_sandbox_activities: bool = True,
        tags: Optional[List[Union[str, pymisp.MISPTag]]] = None,
    ):
        """Convert a contexa telemetry item into objects."""
        objects = []
        file_object = cls.to_file_object(
            file_md5=item["file.md5"],
            file_sha1=item["file.sha1"],
            file_sha256=item["file.sha256"],
            file_name=item["file.name"],
            mime_type=item["file.mime_type"],
            size=item["file.size"],
        )
        objects.append(file_object)

        sandbox_object = None
        if include_sandbox_result:
            sandbox_object = pymisp.MISPObject(name="sandbox-report")
            sandbox_object.add_attribute("score", item["task.score"])
            sandbox_object.add_attribute("saas-sandbox", "vmware-atp-sandbox")
            sandbox_object.add_attribute("permalink", item["task.portal_url"])
            sandbox_object.add_reference(
                referenced_uuid=file_object.uuid,
                relationship_type="belongs-to",
            )
            objects.append(sandbox_object)

        if sandbox_object and include_sandbox_activities and item["analysis.activities"]:
            sig_object = pymisp.MISPObject(name="sb-signature")
            for activity in item["analysis.activities"]:
                sig_object.add_attribute("signature", type="text", value=activity)
            sig_object.add_reference(
                referenced_uuid=sandbox_object.uuid,
                relationship_type="belongs-to",
            )
            objects.append(sig_object)

        technique_tags = []
        if mitre_attack_galaxy_cluster:
            id_to_tag = {
                x["meta"]["external_id"]: x["tag_name"]
                for x in mitre_attack_galaxy_cluster["values"]
            }
            for technique in item["analysis.mitre_techniques"]:
                technique_id = technique.split(":")[0]
                if technique_id in id_to_tag:
                    technique_tags.append(id_to_tag[technique_id])

        contexa_tags = []
        for tag_name, tag_value in zip(item["research.tag.name"], item["research.tag.value"]):
            contexa_tags.append(f"contexa:{tag_name}={tag_value}")

        for tag in itertools.chain(tags or [], technique_tags, contexa_tags):
            TagUtils.add_tag_to_object(file_object, tag)
        return objects

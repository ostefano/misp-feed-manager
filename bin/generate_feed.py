#!/usr/bin/env python3
import argparse
import sys
import pymisp
import pymisp.tools

from feed_manager import generator


def main():
    """Simple script to generate a daily feed."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-o",
        "--output-dir",
        dest="output_dir",
        type=str,
        default="./tmp/",
        help="the local feed",
    )
    args = parser.parse_args()

    file_object = pymisp.tools.GenericObjectGenerator("file")
    print(file_object.uuid)
    file_object.add_attribute("md5", "a" * 32)
    print(file_object.uuid)
    file_object.add_attribute("sha1", "a" * 40)
    print(file_object.uuid)
    file_object.add_attribute("sha256", "a" * 48)
    print(file_object.uuid)

    tag_1 = pymisp.MISPTag()
    tag_1.from_dict(name='misp-galaxy:malpedia="GootKit"')
    tag_2 = pymisp.MISPTag()
    tag_2.from_dict(name='misp-galaxy:threat-actor="Sofacy"')

    # there is no way to assign a tag to an object, so we assign it to all its attributes
    # https://github.com/MISP/MISP/issues/2638
    for attribute in file_object.attributes:
        attribute.add_tag(tag_1)
        attribute.add_tag(tag_2)

    gen = generator.DailyFeedGenerator(args.output_dir, "Prefix")
    gen.add_object_to_event(file_object)
    gen.flush_event()
    return 0


if __name__ == "__main__":
    sys.exit(main())

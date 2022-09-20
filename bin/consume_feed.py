#!/usr/bin/env python3
import argparse
import datetime
import pathlib
import sys


from feed_manager import consumer


def main():
    """Simple script to generate a daily feed."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--input-dir",
        dest="input_dir",
        type=str,
        default="./tmp/",
        help="the local feed",
    )
    parser.add_argument(
        "-t",
        "--indicator-type",
        dest="indicator_type",
        type=str,
        default="sha1",
        help="the indicator type",
    )
    parser.add_argument(
        "-d",
        "--day-delta",
        dest="day_delta",
        type=int,
        default=52,
        help="the look back in terms of days",
    )
    args = parser.parse_args()

    pathlib.Path(args.input_dir).mkdir(parents=True, exist_ok=True)
    since_date_object = datetime.datetime.utcnow() - datetime.timedelta(days=args.day_delta)
    feed_consumer = consumer.LocalFeedConsumer(args.input_dir)
    indicators = feed_consumer.get_indicators_since(
        date_object=since_date_object,
        indicator_type=args.indicator_type,
    )
    print(f"Fetching indicators since {since_date_object}")
    for indicator in indicators:
        print(indicator)
    return 0


if __name__ == "__main__":
    sys.exit(main())

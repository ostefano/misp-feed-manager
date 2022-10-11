# MISP Feed Manager

Utilities and classes to generate and consume MISP feeds.

We support two types of feeds:
1) Indicators feeds: made of simple objects, like hashes, domains, etc; this is the basic feed type
we use to share labelled indicators.
2) Telemetry feeds: made of complex objects coming from our telemetry; each item has multiple
indicators associated (for example md5 and sha1) and can contain complex objects (for example
the list of behaviors associated to a sandbox analysis).

Below we give an example of both. The `generate_feed.py` provides an example of how both feeds
can be generated:

```bash
./bin/generate_feed.py -o ./tmp/
> Daily feed of indicators written to: ./tmp/indicators
> Daily feed of telemetry objects written to: ./tmp/telemetry
```

Consuming an indicator feed extracts all attributes and print them as separate entities; note that
it is still possible to group them by object (file) as the object uuid is not discarded and included
in the provided output; this is useful because, for example, many hashes might describe the same
file.

```bash
./bin/consume_feed.py -i ./tmp/indicators
> Fetching items since 2022-08-20 13:19:04.856733
> {
>  "tags": [
>   "misp-galaxy:malpedia=\"GootKit\"",
>   "misp-galaxy:threat-actor=\"Sofacy\""
>  ],
>  "timestamp": "2022-10-11 14:01:56",
>  "event_uuid": "ca324c99-a9d2-45e0-947d-d864d70df9c5",
>  "object_uuid": "31ae2789-392e-40a7-971b-d80ee8f78fca",
>  "attribute_uuid": "0bd619cc-4692-4c5e-84fd-c45fcd0e0d93",
>  "attribute_type": "md5",
>  "attribute_value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
> }
> {
>  "tags": [
>   "misp-galaxy:malpedia=\"GootKit\"",
>   "misp-galaxy:threat-actor=\"Sofacy\""
>  ],
>  "timestamp": "2022-10-11 14:01:56",
>  "event_uuid": "ca324c99-a9d2-45e0-947d-d864d70df9c5",
>  "object_uuid": "31ae2789-392e-40a7-971b-d80ee8f78fca",
>  "attribute_uuid": "6c6578a9-fd33-4ae9-8443-2bdb0435aa9f",
>  "attribute_type": "sha1",
>  "attribute_value": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
> }
> {
>  "tags": [
>   "misp-galaxy:malpedia=\"GootKit\"",
>   "misp-galaxy:threat-actor=\"Sofacy\""
>  ],
>  "timestamp": "2022-10-11 14:01:56",
>  "event_uuid": "ca324c99-a9d2-45e0-947d-d864d70df9c5",
>  "object_uuid": "31ae2789-392e-40a7-971b-d80ee8f78fca",
>  "attribute_uuid": "6929d4ca-3b14-4d7b-a021-f3442b0eca01",
>  "attribute_type": "sha256",
>  "attribute_value": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
> }
```

Instead of further filtering and processing, it is also possible to request the attribute type
at consumption time. For example, when processing the same feed we can do the following:

```bash
./bin/consume_feed.py -i ./tmp/indicators -t sha1
> Fetching items since 2022-08-20 13:23:48.005220
> {
>  "tags": [
>   "misp-galaxy:malpedia=\"GootKit\"",
>   "misp-galaxy:threat-actor=\"Sofacy\""
>  ],
>  "timestamp": "2022-10-11 14:01:56",
>  "event_uuid": "ca324c99-a9d2-45e0-947d-d864d70df9c5",
>  "object_uuid": "31ae2789-392e-40a7-971b-d80ee8f78fca",
>  "attribute_uuid": "6c6578a9-fd33-4ae9-8443-2bdb0435aa9f",
>  "attribute_type": "sha1",
>  "attribute_value": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
> }
```

And finally, an example of consuming a telemetry feed:
```bash
./bin/consume_feed.py -i ./tmp/telemetry/
> Fetching items since 2022-08-20 13:12:12.802821
> {
>  "tags": [],
>  "techniques": [],
>  "task.portal_url": "https://user.lastline.com/portal#/analyst/task/30f48c17e9db002005baa7d440ca275a/overview",
>  "task.score": "70",
>  "analysis.activities": [
>   "Anomaly: AI detected possible malicious code reuse",
>   "Evasion: Detecting the presence of AntiMalware Scan Interface (AMSI)",
>   "Execution: Subject crash detected",
>   "Signature: Potentially malicious application/program"
>  ],
>  "file.md5": "37840d4e937db0385b820d4019071540",
>  "file.sha1": "a1f7670cd7da7e331db2d69f0855858985819873",
>  "file.sha256": "492bfe8d2b1105ec4045f96913d38f98e30fe349ea50cc4aaa425ca289af2852",
>  "file.name": "unknown"
> }
```

# MISP Feed Manager

Utilities and classes to generate and consume MISP feeds.

```bash
./bin/generate_feed.py 
> a72dd6c2-1be0-48c1-8da6-36ebb5893f85
> a72dd6c2-1be0-48c1-8da6-36ebb5893f85
> a72dd6c2-1be0-48c1-8da6-36ebb5893f85
> a72dd6c2-1be0-48c1-8da6-36ebb5893f85
```

```bash
./bin/consume_feed.py
> Fetching indicators since 2022-07-30 14:25:18.856521
> {'timestamp': '2022-09-20 15:08:34', 'event_uuid': '267821c4-ef6f-4303-9e6a-1fb0461a0577', 'object_uuid': '15f7f63e-6b94-4436-9e8d-3c5e829b2eea', 'attribute_uuid': 'ed8c57dc-a8b4-4a08-8b98-8f9acc544d75', 'indicator': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'tags': ['misp-galaxy:malpedia="GootKit"', 'misp-galaxy:threat-actor="Sofacy"']}
```

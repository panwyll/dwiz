def compact_records(records: list[dict]) -> list[dict]:
    latest = {}
    for record in records:
        key = record.get("id")
        if key is None:
            continue
        latest[key] = record
    return list(latest.values())

from libs.jobs.compaction import compact_records


def test_compact_records_keeps_latest_by_id() -> None:
    records = [
        {"id": "a", "value": 1},
        {"id": "b", "value": 2},
        {"id": "a", "value": 3},
    ]
    result = compact_records(records)
    assert {item["id"]: item["value"] for item in result} == {"a": 3, "b": 2}

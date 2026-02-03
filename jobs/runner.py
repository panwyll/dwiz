from libs.jobs.compaction import compact_records


def main() -> None:
    records = [{"id": "1", "value": "a"}, {"id": "1", "value": "b"}]
    print(compact_records(records))


if __name__ == "__main__":
    main()

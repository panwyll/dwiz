import pathlib

PIPELINES_ROOT = pathlib.Path(__file__).resolve().parents[1] / "pipelines"
REQUIRED_KEYS = {"name", "owner"}


def validate_yaml(path: pathlib.Path) -> list[str]:
    errors = []
    content = path.read_text().splitlines()
    keys = set()
    for line in content:
        if ":" in line:
            key = line.split(":", 1)[0].strip()
            if key:
                keys.add(key)
    missing = REQUIRED_KEYS - keys
    if missing:
        errors.append(f"{path.name} missing {', '.join(sorted(missing))}")
    return errors


def main() -> None:
    errors = []
    for path in PIPELINES_ROOT.rglob("*.yaml"):
        errors.extend(validate_yaml(path))
    if errors:
        raise SystemExit("\n".join(errors))


if __name__ == "__main__":
    main()

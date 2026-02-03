import ast
import pathlib

DAG_ROOT = pathlib.Path(__file__).resolve().parents[1] / "dags"
REQUIRED_ATTRS = {"owner", "tags", "schedule_interval", "catchup", "max_active_runs"}


def validate_file(path: pathlib.Path) -> list[str]:
    errors = []
    tree = ast.parse(path.read_text())
    assigns = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigns.add(target.id)
    missing = REQUIRED_ATTRS - assigns
    if missing:
        errors.append(f"{path.name} missing {', '.join(sorted(missing))}")
    return errors


def main() -> None:
    errors = []
    for path in DAG_ROOT.glob("*.py"):
        errors.extend(validate_file(path))
    if errors:
        raise SystemExit("\n".join(errors))


if __name__ == "__main__":
    main()

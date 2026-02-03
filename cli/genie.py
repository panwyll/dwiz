#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TERRAFORM_ENVS = {"dev", "prod"}


def run(cmd: list[str], cwd: Path | None = None) -> None:
    result = subprocess.run(cmd, cwd=cwd, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def require_tools(*tools: str) -> None:
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        raise SystemExit(f"Missing required tools: {', '.join(missing)}")


def run_make(target: str, env: str | None = None) -> None:
    env_vars = os.environ.copy()
    if env:
        env_vars["ENV"] = env
    result = subprocess.run(["make", target], cwd=REPO_ROOT, env=env_vars, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def cmd_init(_: argparse.Namespace) -> None:
    require_tools("terraform", "aws")
    print("Initialized. Ensure terraform backend config is updated.")


def cmd_up(args: argparse.Namespace) -> None:
    require_tools("terraform")
    if args.env not in TERRAFORM_ENVS:
        raise SystemExit("env must be dev or prod")
    run_make("tf-init", args.env)
    run_make("tf-plan", args.env)
    run_make("tf-apply", args.env)


def cmd_deploy(args: argparse.Namespace) -> None:
    require_tools("aws")
    if args.env not in TERRAFORM_ENVS:
        raise SystemExit("env must be dev or prod")
    run_make("deploy")


def cmd_new_source(args: argparse.Namespace) -> None:
    source_dir = REPO_ROOT / "pipelines" / "sources"
    source_dir.mkdir(parents=True, exist_ok=True)
    path = source_dir / f"{args.name}.yaml"
    if path.exists():
        raise SystemExit("source already exists")
    path.write_text("name: {name}\nowner: data-eng\n".format(name=args.name))
    print(f"Created {path}")


def cmd_add_stream(args: argparse.Namespace) -> None:
    stream_dir = REPO_ROOT / "pipelines" / "streams"
    stream_dir.mkdir(parents=True, exist_ok=True)
    path = stream_dir / f"{args.name}.yaml"
    if path.exists():
        raise SystemExit("stream already exists")
    path.write_text(
        "name: {name}\nowner: data-eng\nsource: example\n".format(name=args.name)
    )
    print(f"Created {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="genie")
    sub = parser.add_subparsers(dest="command", required=True)

    init_parser = sub.add_parser("init", help="Verify prerequisites")
    init_parser.set_defaults(func=cmd_init)

    up_parser = sub.add_parser("up", help="Provision infra")
    up_parser.add_argument("env")
    up_parser.set_defaults(func=cmd_up)

    deploy_parser = sub.add_parser("deploy", help="Deploy DAGs")
    deploy_parser.add_argument("env")
    deploy_parser.set_defaults(func=cmd_deploy)

    new_source = sub.add_parser("new-source", help="Create source scaffold")
    new_source.add_argument("name")
    new_source.set_defaults(func=cmd_new_source)

    add_stream = sub.add_parser("add-stream", help="Create stream scaffold")
    add_stream.add_argument("name")
    add_stream.set_defaults(func=cmd_add_stream)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

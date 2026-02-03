PYTHON := python3

.PHONY: lint test format dag-validate tf-init tf-plan tf-apply tf-fmt build deploy

lint:
	$(PYTHON) -m ruff check .

format:
	$(PYTHON) -m ruff format .

test:
	$(PYTHON) -m pytest

dag-validate:
	$(PYTHON) scripts/validate_dags.py

tf-init:
	terraform -chdir=terraform/envs/$(ENV) init

tf-plan:
	terraform -chdir=terraform/envs/$(ENV) plan

tf-apply:
	terraform -chdir=terraform/envs/$(ENV) apply -auto-approve

tf-fmt:
	terraform fmt -recursive

build:
	./scripts/build_and_push.sh

deploy:
	./scripts/deploy_dags.sh

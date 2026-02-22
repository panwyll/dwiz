PYTHON := python3

.PHONY: install lint test format dag-validate tf-init tf-plan tf-apply tf-destroy tf-unlock tf-check-lock tf-fmt build deploy

install:
	$(PYTHON) -m pip install -e .

lint:
	$(PYTHON) -m ruff check .

format:
	$(PYTHON) -m ruff format .

test:
	$(PYTHON) -m pytest

dag-validate:
	$(PYTHON) scripts/validate_dags.py
	$(PYTHON) scripts/policy_check.py

tf-init:
	./scripts/ensure_backend.sh $(ENV)
	terraform -chdir=terraform/envs/$(ENV) init $(TF_INIT_FLAGS)

tf-check-lock:
	./scripts/check_state_lock.sh $(ENV) $(MAX_RETRIES) $(RETRY_DELAY)

tf-plan:
	./scripts/check_state_lock.sh $(ENV) 3 15 || true
	terraform -chdir=terraform/envs/$(ENV) plan

tf-apply:
	./scripts/tf_apply_wrapper.sh $(ENV)

tf-destroy:
	terraform -chdir=terraform/envs/$(ENV) destroy -auto-approve

tf-unlock:
	./scripts/tf_force_unlock.sh $(ENV) $(LOCK_ID)

tf-fmt:
	terraform fmt -recursive

build:
	./scripts/build_and_push.sh

deploy:
	./scripts/deploy_dags.sh $(ENV)

from datetime import datetime

from airflow import DAG
from airflow.operators.python import PythonOperator

from libs.python_common.logging import configure_logging
from libs.python_common.metrics import emit_metric
from libs.python_common.secrets import get_secret_value  # noqa: F401

owner = "data-eng"
tags = ["batch", "api"]
schedule_interval = "0 2 * * *"
catchup = False
max_active_runs = 1


def ingest_api() -> None:
    configure_logging()
    
    # Example: Retrieve API key from AWS Secrets Manager
    # Replace 'genie-dev' with your actual secret prefix
    # api_key = get_secret_value("genie-dev/api-keys", "example_api_key")
    # Use api_key to authenticate with external API
    
    emit_metric("batch_api_ingest_runs", 1, source="example")


def freshness_check() -> None:
    emit_metric("batch_api_ingest_freshness", 1, source="example")


with DAG(
    dag_id="batch_api_ingest",
    start_date=datetime(2024, 1, 1),
    schedule_interval=schedule_interval,
    catchup=catchup,
    max_active_runs=max_active_runs,
    tags=tags,
    default_args={"owner": owner},
) as dag:
    ingest = PythonOperator(task_id="ingest", python_callable=ingest_api)
    freshness = PythonOperator(task_id="freshness_check", python_callable=freshness_check)

    ingest >> freshness

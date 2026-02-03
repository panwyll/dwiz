from datetime import datetime

from airflow import DAG
from airflow.operators.python import PythonOperator

from libs.python_common.logging import configure_logging
from libs.python_common.metrics import emit_metric

owner = "data-eng"
tags = ["batch", "api"]
schedule_interval = "0 2 * * *"
catchup = False
max_active_runs = 1


def ingest_api() -> None:
    configure_logging()
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

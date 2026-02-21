from datetime import datetime

from airflow import DAG
from airflow.operators.python import PythonOperator

from libs.python_common.logging import configure_logging
from libs.python_common.metrics import emit_metric
from libs.python_common.secrets import get_secret_value  # noqa: F401

owner = "data-eng"
tags = ["stream", "compaction"]
schedule_interval = "0 * * * *"
catchup = False
max_active_runs = 1


def compact_stream() -> None:
    configure_logging()
    
    # Example: Retrieve streaming credentials from AWS Secrets Manager
    # Replace 'wizard-dev' with your actual secret prefix
    # stream_creds = get_secret_value("wizard-dev/streaming", "stream_api_key")
    # Use credentials to access streaming service
    
    emit_metric("stream_compaction_runs", 1, stream="example")


def freshness_check() -> None:
    emit_metric("stream_compaction_freshness", 1, stream="example")


with DAG(
    dag_id="stream_compaction",
    start_date=datetime(2024, 1, 1),
    schedule_interval=schedule_interval,
    catchup=catchup,
    max_active_runs=max_active_runs,
    tags=tags,
    default_args={"owner": owner},
) as dag:
    compact = PythonOperator(task_id="compact", python_callable=compact_stream)
    freshness = PythonOperator(task_id="freshness_check", python_callable=freshness_check)

    compact >> freshness

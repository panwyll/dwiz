import logging
from typing import Any

logger = logging.getLogger("genie")


def emit_metric(name: str, value: float, **dimensions: Any) -> None:
    payload = {"metric": name, "value": value, "dimensions": dimensions}
    logger.info("metric", extra=payload)

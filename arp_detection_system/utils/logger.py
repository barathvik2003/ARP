import logging
import os
import sys
from datetime import datetime
from typing import Optional


LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs_data")
os.makedirs(LOG_DIR, exist_ok=True)


def get_logger(name: str, level: int = logging.INFO, log_file: Optional[str] = None) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    logger.addHandler(console)

    if log_file is None:
        log_file = os.path.join(LOG_DIR, f"{name}_{datetime.now():%Y%m%d}.log")
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


def get_alert_logger() -> logging.Logger:
    return get_logger("alerts", logging.WARNING, os.path.join(LOG_DIR, "alerts.log"))


def get_audit_logger() -> logging.Logger:
    return get_logger("audit", logging.INFO, os.path.join(LOG_DIR, "audit.log"))

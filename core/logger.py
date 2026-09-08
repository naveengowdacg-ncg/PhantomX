import logging
from pathlib import Path

def get_logger():
    Path("reports").mkdir(exist_ok=True)
    logger = logging.getLogger("cybersec")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler("reports/execution.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(handler)
    return logger

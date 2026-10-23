import logging
from pathlib import Path

def get_logger(reports_dir="reports"):
    reports_path = Path(reports_dir)
    reports_path.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("cybersec")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler(reports_path / "execution.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(handler)
    return logger

import logging
from pathlib import Path

def setup_logger(log_dir="logs"):
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("packet_monitor")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    fh = logging.FileHandler(Path(log_dir) / "packets.log", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler(fh)
    return logger

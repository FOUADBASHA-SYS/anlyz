"""
Dedicated background worker process.
Continuously runs scheduled watchlist scans, batch processing, and queue jobs in containerized deployments.
"""
import time
import logging
from backend.services.watchlist_service import run_due_watchlist_scans
from backend.database import Base, engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WORKER] %(levelname)s: %(message)s"
)
logger = logging.getLogger("xdr.worker")


def run_worker():
    logger.info("Initializing XDR URL Analyzer Worker process...")
    Base.metadata.create_all(bind=engine)
    logger.info("Worker database connection established.")

    while True:
        try:
            run_due_watchlist_scans()
        except Exception as e:
            logger.error("Error during scheduled watchlist execution: %s", e)
        time.sleep(15)


if __name__ == "__main__":
    run_worker()

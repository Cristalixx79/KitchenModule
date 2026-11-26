import logging
import threading
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("queue_processor_integrated")


class QueueProcessor:
    def __init__(self, dbi_client, interval_seconds: int = 10):
        self.dbi_client = dbi_client
        self.interval = interval_seconds
        self.running = False
        self.thread = None

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._process_loop, daemon=True)
        self.thread.start()
        logger.info("queue processor started")

    def stop(self) -> None:
        self.running = False
        if self.thread:
            self.thread.join()
        logger.info("queue processor stopped")

    def _process_loop(self) -> None:
        while self.running:
            try:
                self.dbi_client.process_queue()
            except Exception:
                logger.exception("error in queue processor")
            time.sleep(self.interval)
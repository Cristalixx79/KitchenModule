import logging
import queue
import threading

logger = logging.getLogger("gateway_worker")


class GatewayWorker(threading.Thread):
    def __init__(self, input_queue: queue.Queue, dbi_client):
        super().__init__(daemon=True)
        self.stop_event = threading.Event()
        self._in = input_queue
        self._dbi = dbi_client

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                event = self._in.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._dbi.send_with_queue(event)
            except Exception:
                # Не логируем содержимое события.
                logger.exception("gateway: failed to enqueue/send event")

    def stop(self) -> None:
        self.stop_event.set()
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

    def run(self):
        while not self.stop_event.is_set():
            try:
                payload = self._in.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._dbi.send_with_queue(payload)
            except Exception:
                logger.exception("gateway: failed to send %s", payload.get("event_type"))

    def stop(self):
        self.stop_event.set()

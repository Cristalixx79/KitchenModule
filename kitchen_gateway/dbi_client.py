from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any, Optional, Tuple

import requests

from .db_queue import DBQueue
from .pydantic_models import (
    ActionEventLn,
    AuditClipLn,
    DataQualityEventLn,
    EnvironmentStateLn,
    HygieneCheckLn,
    ProcessEventLn,
    SanitaryEventLn,
)

logger = logging.getLogger("dbi_client_integrated")

MODELS = {
    "action": ActionEventLn,
    "hygiene_check": HygieneCheckLn,
    "sanitary_event": SanitaryEventLn,
    "process_event": ProcessEventLn,
    "data_quality_event": DataQualityEventLn,
    "environment_state": EnvironmentStateLn,
    "audit_clip": AuditClipLn,
}

KEY_FIELDS = {
    "action": "action_id",
    "hygiene_check": "check_id",
    "sanitary_event": "event_id",
    "process_event": "event_id",
    "data_quality_event": "event_id",
    "environment_state": "state_id",
    "audit_clip": "clip_id",
}

OLD_EVENT_TYPE_TO_KIND = {
    "action_event": "action",
    "hygiene_check": "hygiene_check",
    "sanitary_event": "sanitary_event",
    "process_event": "process_event",
    "data_quality_event": "data_quality_event",
    "environment_state": "environment_state",
    "audit_clip": "audit_clip",
}


class DBIClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        db_path: Optional[str] = None,
        restaurant_id: Optional[int] = None,
    ):
        self._base_url = (base_url or os.environ["DBI_URL"]).rstrip("/")
        self._token = token or os.environ["DBI_SERVICE_TOKEN"]
        self._restaurant_id = int(restaurant_id or os.environ["RESTAURANT_ID"])
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            }
        )
        self._db_queue = DBQueue(db_path or os.getenv("DB_QUEUE_PATH", "./db_queue.db"))

    def _coerce_payload(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        p = dict(payload)

        if p.get("employee_id") == "":
            p["employee_id"] = None

        if kind == "sanitary_event":
            if "event_id" not in p and "sanitary_event_id" in p:
                p["event_id"] = p.pop("sanitary_event_id")
            if "event_type" not in p and "sanitary_event_type" in p:
                p["event_type"] = p.pop("sanitary_event_type")

        if kind == "process_event":
            if "event_id" not in p and "process_event_id" in p:
                p["event_id"] = p.pop("process_event_id")
            if "event_type" not in p and "process_event_type" in p:
                p["event_type"] = p.pop("process_event_type")

        if kind == "hygiene_check" and "check_id" not in p and "hygiene_check_id" in p:
            p["check_id"] = p.pop("hygiene_check_id")

        if kind == "environment_state" and "state_id" not in p and "environment_state_id" in p:
            p["state_id"] = p.pop("environment_state_id")

        if kind == "audit_clip" and "clip_id" not in p and "audit_clip_id" in p:
            p["clip_id"] = p.pop("audit_clip_id")

        if kind == "data_quality_event" and "event_id" not in p and "data_quality_event_id" in p:
            p["event_id"] = p.pop("data_quality_event_id")

        if "occurred_at" not in p and "timestamp" in p:
            p["occurred_at"] = p.pop("timestamp")

        p.setdefault("restaurant_id", self._restaurant_id)
        return p

    def _prepare(self, event: dict[str, Any]) -> Tuple[str, dict[str, Any], str]:
        if "kind" in event:
            kind = str(event["kind"]).lower()
            payload = dict(event.get("payload") or {})
        else:
            old_type = str(event.get("event_type", "")).lower()
            kind = OLD_EVENT_TYPE_TO_KIND.get(old_type, old_type)
            payload = {k: v for k, v in event.items() if k != "event_type"}

        payload = self._coerce_payload(kind, payload)
        model = MODELS[kind]
        obj = model.model_validate(payload)
        clean = obj.model_dump(mode="json", exclude_none=True)

        key_field = KEY_FIELDS[kind]
        key = str(clean.get(key_field) or uuid.uuid4())
        clean[key_field] = key
        return kind, clean, key

    def _send_request(self, kind: str, payload: dict[str, Any]) -> tuple[str, str]:
        url = f"{self._base_url}/ingest/{kind}"
        try:
            response = self._session.post(url, json=payload, timeout=20)
        except requests.RequestException as exc:
            return "retry", str(exc)

        if response.status_code == 503 or response.status_code >= 500:
            return "retry", f"http {response.status_code}"

        try:
            data = response.json()
        except ValueError:
            data = {}

        verdict = str(data.get("verdict", "")).lower()
        reason = str(data.get("reason", "")) or f"http {response.status_code}"

        if verdict in ("accepted", "duplicate"):
            return verdict, ""
        if verdict == "rejected":
            return "rejected", reason
        if response.status_code in (400, 401, 403, 404, 409, 422):
            return "rejected", reason
        return "retry", reason

    def _process_queue_item(self, event_id: int) -> None:
        row = self._db_queue.get_event(event_id)
        if not row or row["status"] != "pending":
            return

        kind = row["kind"]
        payload = json.loads(row["payload_json"])
        verdict, reason = self._send_request(kind, payload)

        if verdict in ("accepted", "duplicate"):
            self._db_queue.complete_event(event_id)
            return
        if verdict == "rejected":
            self._db_queue.reject_event(event_id, reason)
            logger.error(
                "DBI rejected event kind=%s key=%s reason=%s",
                kind,
                row["idempotency_key"],
                reason,
            )
            return

        self._db_queue.retry_event(event_id, reason)
        logger.warning(
            "DBI delivery retry scheduled kind=%s key=%s reason=%s",
            kind,
            row["idempotency_key"],
            reason,
        )

    def send_with_queue(self, event: dict[str, Any]) -> None:
        try:
            kind, payload, key = self._prepare(event)
        except Exception as exc:
            # Не печатаем payload: в нём могут быть employee_id.
            logger.error("event validation failed: %s", exc)
            return

        event_id = self._db_queue.add_database_event(
            {"kind": kind, "payload": payload, "idempotency_key": key}
        )
        if event_id is None:
            logger.error("queue insert failed kind=%s key=%s", kind, key)
            return
        self._process_queue_item(event_id)

    def process_queue(self) -> None:
        self._db_queue.check_size_and_cleanup()
        for row in self._db_queue.get_database_events(limit=20):
            self._process_queue_item(int(row["id"]))
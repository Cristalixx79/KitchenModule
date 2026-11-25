import logging
import queue
import threading
import time
import uuid
from collections import OrderedDict, defaultdict, deque
from typing import Any, Dict, List, Optional

logger = logging.getLogger("event_aggregator")

DEFAULT_CONFIG: Dict[str, Any] = {
    "threshold_employee_interrupt": 0.5,
    "T_resume_interrupt_sec": 60.0,
    "min_action_duration_for_interrupt_sec": 0.8,
    "handoff_confirm_window_sec": 2.0,
    "risk_hold_margin_sec": 1.0,
    "emit_zero_risk_score": True,
    "w_left_zone": 10,
    "w_carrying_tool": 25,
    "w_carrying_food": 25,
    "w_intrusion": 20,
    "level_info_lt": 25,
    "level_warning_lt": 45,
    "employee_confidence_floor": 0.5,
    "T_violation_dedup_sec": 30.0,
    "clip_for_sanitary_violation": True,
    "clip_for_process_event": False,
    "clip_for_data_quality_obs_lost": False,
    "idempotency_cache_size": 10000,
    "state_ttl_sec": 300.0,
    "restaurant_id": None,
}

SEVERITY_MAP = {
    "critical": "violation", "high": "violation", "violation": "violation",
    "medium": "warning", "low": "warning", "warning": "warning", "info": "info",
}
SEVERITY_CAPPED = {"critical", "high", "violation"}
ESCALATIONS = {
    "alcohol_consumption_in_work_zone": "alcohol_escalation",
    "smoking_in_work_zone": "smoking_escalation",
}
UNESTABLISHED = {"anonymous_track", "unresolved"}
FINAL_DECISIONS = {
    "SANITARY_VIOLATION_CONFIRMED", "PROCESS_EVENT_CONFIRMED", "DATA_QUALITY_EVENT_CONFIRMED",
    "UNRESOLVED_DUE_TO_DATA_QUALITY", "NO_EVENT",
}
PROCESS_TYPES = {
    "food_handoff": "food_handoff",
    "action_interruption": "ACTION_INTERRUPTION",
    "zone_risk_score": "ZONE_RISK_SCORE",
}
PASSTHROUGH = {
    "hygiene_check": "HYGIENE_CHECK",
    "environment_state": "ENVIRONMENT_STATE",
    "audit_clip": "AUDIT_CLIP",
}
ID_FIELD = {
    "ACTION_EVENT": "action_id",
    "HYGIENE_CHECK": "hygiene_check_id",
    "SANITARY_EVENT": "sanitary_event_id",
    "PROCESS_EVENT": "process_event_id",
    "DATA_QUALITY_EVENT": "data_quality_event_id",
    "ENVIRONMENT_STATE": "environment_state_id",
    "AUDIT_CLIP": "audit_clip_id",
}


def _ms(value) -> int:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return int(time.time() * 1000)
    return int(v if v > 1e12 else v * 1000)


def _float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _clamp(value: float) -> float:
    return min(1.0, max(0.0, value))


def _employee(value) -> Optional[str]:
    return None if value in (None, "", "undefined") else str(value)


def _employee_of(event: Dict, payload: Dict) -> Optional[str]:
    value = payload.get("employee_id")
    if value in (None, "", "undefined") and event.get("entity_type") == "employee":
        value = event.get("entity_id")
    return _employee(value)


def _compact(data: Dict) -> Dict:
    return {k: v for k, v in data.items() if v is not None}


def _same_place(zone_a, cam_a, zone_b, cam_b) -> bool:
    return (zone_a is not None and zone_a == zone_b) or (cam_a is not None and cam_a == cam_b)


class EventAggregator(threading.Thread):
    def __init__(self, input_queue: queue.Queue, out_queue: queue.Queue,
                 config: Optional[Dict[str, Any]] = None):
        super().__init__(daemon=True)
        self.stop_event = threading.Event()
        self.stats: Dict[str, int] = defaultdict(int)
        self.cfg = {**DEFAULT_CONFIG, **(config or {})}
        self._in = input_queue
        self._out = out_queue

        self._seen: OrderedDict = OrderedDict()
        self._actions: Dict[str, Dict[str, Any]] = {}
        self._left_zone: Dict[tuple, Dict[str, Any]] = {}
        self._violation_last: Dict[tuple, int] = {}
        self._intrusions: deque = deque()
        self._pending_risk: List[Dict[str, Any]] = []
        self._last_gc = time.monotonic()

        self._handlers = {
            "action_start": self._on_action_start,
            "action_end": self._on_action_end,
            "sanitary_event": self._on_sanitary,
            "process_event": self._on_process,
            "data_quality_event": self._on_data_quality,
            **{name: self._on_passthrough for name in PASSTHROUGH},
        }

    def run(self):
        while not self.stop_event.is_set():
            try:
                event = self._in.get(timeout=0.25)
            except queue.Empty:
                event = None
            try:
                payloads = self.process(event)
            except Exception:
                logger.exception("event_aggregator: processing failed")
                continue
            self._emit(payloads)

    def stop(self):
        self.stop_event.set()

    def process(self, event: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if event is not None:
            handler = self._handlers.get(str(event.get("event_type", "")).lower())
            if handler is None:
                self.stats["ignored"] += 1
            else:
                out += handler(event)
        return out + self.tick()

    def tick(self, now: Optional[float] = None) -> List[Dict[str, Any]]:
        now = time.monotonic() if now is None else now
        due = [e for e in self._pending_risk if e["due"] <= now]
        self._pending_risk = [e for e in self._pending_risk if e["due"] > now]
        out: List[Dict[str, Any]] = []
        for entry in due:
            out += self._risk_event(entry)
        self._gc(now)
        return out

    def _emit(self, payloads: List[Dict[str, Any]]):
        for payload in payloads:
            try:
                self._out.put_nowait(payload)
            except queue.Full:
                self.stats["dropped_out_queue_full"] += 1
                logger.error("gateway queue is full, %s dropped", payload.get("event_type"))

    def _ship(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        out_type = payload["event_type"]
        key = f"{out_type}:{payload[ID_FIELD[out_type]]}"
        if key in self._seen:
            self.stats["suppressed_duplicate"] += 1
            return []
        self._seen[key] = None
        while len(self._seen) > self.cfg["idempotency_cache_size"]:
            self._seen.popitem(last=False)
        payload = _compact(payload)
        if self.cfg["restaurant_id"] is not None:
            payload.setdefault("restaurant_id", self.cfg["restaurant_id"])
        self.stats[f"shipped_{out_type}"] += 1
        return [payload]

    def _clip(self, event: Dict, link_field: str, link_id: str) -> List[Dict[str, Any]]:
        clip_id = event.get("audit_clip_id")
        if not clip_id:
            return []
        return self._ship({
            "event_type": "AUDIT_CLIP",
            "audit_clip_id": clip_id,
            link_field: link_id,
            "camera_id": event.get("camera_id"),
            "timestamp": _ms(event.get("timestamp")),
        })

    @staticmethod
    def _provenance(event: Dict) -> Dict[str, Any]:
        keys = ("track_lineage_id", "executor_attribution", "rules_config_version",
                "model_versions", "decision_trace", "time_source", "late")
        return {k: event[k] for k in keys if event.get(k) is not None}

    @staticmethod
    def _obs_state(event: Dict, payload: Dict) -> str:
        trace = event.get("decision_trace") or {}
        return str(payload.get("observation_state") or trace.get("observation_state") or "obs_ok").upper()

    @staticmethod
    def _decision(payload: Dict, default: str = "") -> str:
        return str(payload.get("decision_mode") or default).upper()

    def _suppress(self, event: Dict, decision: str):
        self.stats[f"suppressed_{decision.lower() or 'missing'}"] += 1
        if decision not in FINAL_DECISIONS:
            logger.warning("%s %s dropped: decision_mode '%s' is not final",
                           event.get("event_type"), event.get("event_id"), decision)

    def _unestablished(self, confidence, attribution) -> bool:
        if attribution in UNESTABLISHED:
            return True
        return confidence is not None and _float(confidence, 1.0) < self.cfg["employee_confidence_floor"]

    @staticmethod
    def _process_payload(ptype: str, employee_id, zone_id, camera_id, ts: int,
                         details: Dict, raw: Optional[Dict] = None) -> Dict[str, Any]:
        return {
            "event_type": "PROCESS_EVENT",
            "process_event_id": str(uuid.uuid4()),
            "process_event_type": ptype,
            "employee_id": employee_id,
            "zone_id": zone_id,
            "camera_id": camera_id,
            "timestamp": ts,
            "details": details,
            "raw_payload": raw,
        }

    def _on_action_start(self, event: Dict) -> List[Dict[str, Any]]:
        p = event.get("payload") or {}
        state = {
            "ts_start": _ms(event.get("timestamp")),
            "employee_id": _employee_of(event, p),
            "zone_id": p.get("zone_id"),
            "camera_id": event.get("camera_id"),
            "action_type": p.get("action_type"),
            "object_class": p.get("object_class"),
            "seen": time.monotonic(),
        }
        if p.get("action_id"):
            self._actions[p["action_id"]] = state
        return self._detect_interruption(state, p.get("action_id"))

    def _detect_interruption(self, state: Dict, resumed_id: Optional[str]) -> List[Dict[str, Any]]:
        employee_id = state["employee_id"]
        key = (employee_id, state["zone_id"], state["action_type"])
        prev = self._left_zone.get(key) if employee_id else None
        if prev is None:
            return []
        gap = (state["ts_start"] - prev["ts_end"]) / 1000.0
        if gap < 0 or gap > self.cfg["T_resume_interrupt_sec"]:
            return []
        if (prev["employee_confidence"] < self.cfg["threshold_employee_interrupt"]
                or prev["duration"] < self.cfg["min_action_duration_for_interrupt_sec"]):
            return []
        del self._left_zone[key]
        return self._ship(self._process_payload(
            "ACTION_INTERRUPTION", employee_id, state["zone_id"], state["camera_id"], state["ts_start"],
            {
                "interrupted_action_id": prev["action_id"],
                "resumed_action_id": resumed_id,
                "action_type": state["action_type"],
                "resume_gap_sec": round(gap, 3),
            },
        ))

    def _on_action_end(self, event: Dict) -> List[Dict[str, Any]]:
        p = event.get("payload") or {}
        action_id = p.get("action_id") or event.get("event_id") or str(uuid.uuid4())
        start = self._actions.pop(action_id, {})
        ts_end = _ms(event.get("timestamp"))
        ts_start = start.get("ts_start")
        employee_id = _employee_of(event, p)
        employee_confidence = _clamp(_float(p.get("employee_confidence"), _float(event.get("confidence"))))
        duration = max(0.0, _float(p.get("duration"), (ts_end - ts_start) / 1000.0 if ts_start else 0.0))

        payload = {
            "event_type": "ACTION_EVENT",
            "action_id": action_id,
            "employee_id": employee_id,
            "camera_id": event.get("camera_id") or p.get("camera_id"),
            "zone_id": p.get("zone_id") or start.get("zone_id"),
            "action_type": p.get("action_type") or start.get("action_type"),
            "object_class": p.get("object_class") or start.get("object_class"),
            "timestamp_start": ts_start,
            "timestamp_end": ts_end,
            "duration": round(duration, 3),
            "end_reason": p.get("end_reason"),
            "employee_confidence": employee_confidence,
            "carrying_type": p.get("carrying_type") or "none",
            "carrying_confidence": _clamp(_float(p.get("carrying_confidence"), employee_confidence)),
            "confidence": _clamp(_float(event.get("confidence"), employee_confidence)),
            "raw_payload": self._provenance(event),
        }
        out = self._ship(payload)
        if not out:
            return out
        if payload["end_reason"] == "left_zone" and employee_id:
            self._left_zone[(employee_id, payload["zone_id"], payload["action_type"])] = {
                "action_id": action_id,
                "ts_end": ts_end,
                "duration": duration,
                "employee_confidence": employee_confidence,
                "seen": time.monotonic(),
            }
        self._open_risk(event, payload, ts_start or ts_end)
        return out

    def _open_risk(self, event: Dict, action: Dict, ts_from: int):
        self._pending_risk.append({
            "action_id": action["action_id"],
            "employee_id": action["employee_id"],
            "employee_confidence": action["employee_confidence"],
            "zone_id": action["zone_id"],
            "camera_id": action["camera_id"],
            "lineage": event.get("track_lineage_id"),
            "attribution": event.get("executor_attribution"),
            "end_reason": action["end_reason"],
            "carrying_type": action["carrying_type"],
            "ts": action["timestamp_end"],
            "ts_from": ts_from,
            "handoff": False,
            "intrusion": any(
                ts >= ts_from and _same_place(zone, cam, action["zone_id"], action["camera_id"])
                for ts, zone, cam in self._intrusions
            ),
            "due": time.monotonic() + self.cfg["handoff_confirm_window_sec"] + self.cfg["risk_hold_margin_sec"],
        })

    def _risk_event(self, entry: Dict) -> List[Dict[str, Any]]:
        cfg = self.cfg
        factors = {
            "left_zone": cfg["w_left_zone"] if entry["end_reason"] == "left_zone" else 0,
            "carrying_tool": cfg["w_carrying_tool"] if entry["carrying_type"] == "tool" else 0,
            "carrying_food": cfg["w_carrying_food"] if entry["carrying_type"] == "food" and not entry["handoff"] else 0,
            "intrusion": cfg["w_intrusion"] if entry["intrusion"] else 0,
        }
        score = sum(factors.values())
        if score == 0 and not cfg["emit_zero_risk_score"]:
            return []
        if score < cfg["level_info_lt"]:
            level = "info"
        elif score < cfg["level_warning_lt"]:
            level = "warning"
        else:
            level = "violation"
        if level == "violation" and self._unestablished(entry["employee_confidence"], entry["attribution"]):
            level = "warning"
        return self._ship(self._process_payload(
            "ZONE_RISK_SCORE", entry["employee_id"], entry["zone_id"], entry["camera_id"], entry["ts"],
            {"action_id": entry["action_id"], "score": score, "level": level, "factors": factors},
        ))

    def _on_sanitary(self, event: Dict) -> List[Dict[str, Any]]:
        p = event.get("payload") or {}
        stype = p.get("sanitary_event_type")
        decision = self._decision(p)
        ts = _ms(event.get("timestamp"))

        if decision == "UNRESOLVED_DUE_TO_DATA_QUALITY":
            return self._unresolved_to_data_quality(event, p, ts)
        if decision != "SANITARY_VIOLATION_CONFIRMED":
            self._suppress(event, decision)
            return []

        if stype == "intrusion_work_zone":
            self._register_intrusion(ts, p.get("zone_id"), event.get("camera_id"))

        employee_id = _employee_of(event, p)
        key = (stype, employee_id or event.get("track_lineage_id") or event.get("entity_id"), p.get("zone_id"))
        last = self._violation_last.get(key)
        if last is not None and ts - last < self.cfg["T_violation_dedup_sec"] * 1000:
            self.stats["suppressed_violation_dedup"] += 1
            return []

        severity, internal, escalation, original = self._severity(event, p, stype)
        raw = self._provenance(event)
        if original:
            raw["severity_internal_original"] = original
        payload = {
            "event_type": "SANITARY_EVENT",
            "sanitary_event_id": p.get("sanitary_event_id") or event.get("event_id") or str(uuid.uuid4()),
            "sanitary_event_type": stype,
            "source_context": p.get("source_context"),
            "target_context": p.get("target_context"),
            "severity": severity,
            "severity_internal": internal,
            "escalation_category": escalation,
            "incompatibility_cause": p.get("incompatibility_cause"),
            "rule_id": str(p["rule_id"]) if p.get("rule_id") is not None else None,
            "zone_id": p.get("zone_id"),
            "employee_id": employee_id,
            "decision_mode": decision,
            "camera_id": event.get("camera_id"),
            "timestamp": ts,
            "raw_payload": raw,
        }
        out = self._ship(payload)
        if not out:
            return out
        self._violation_last[key] = ts
        if self.cfg["clip_for_sanitary_violation"]:
            out += self._clip(event, "sanitary_event_id", payload["sanitary_event_id"])
        return out

    def _severity(self, event: Dict, payload: Dict, stype: Optional[str]):
        if stype in ESCALATIONS:
            return "violation", "critical", ESCALATIONS[stype], None
        internal = str(payload.get("severity_internal") or payload.get("severity") or "warning").lower()
        confidence = payload.get("employee_confidence", event.get("employee_confidence"))
        original = None
        if internal in SEVERITY_CAPPED and self._unestablished(confidence, event.get("executor_attribution")):
            original, internal = internal, "warning"
        return SEVERITY_MAP.get(internal, "warning"), internal, None, original

    def _unresolved_to_data_quality(self, event: Dict, payload: Dict, ts: int) -> List[Dict[str, Any]]:
        return self._ship({
            "event_type": "DATA_QUALITY_EVENT",
            "data_quality_event_id": str(uuid.uuid4()),
            "reason": "unresolved_due_to_data_quality",
            "employee_id": _employee_of(event, payload),
            "observation_state": self._obs_state(event, payload),
            "suppressed_events": [str(payload.get("sanitary_event_id") or event.get("event_id"))],
            "zone_id": payload.get("zone_id"),
            "camera_id": event.get("camera_id"),
            "timestamp": ts,
            "raw_payload": self._provenance(event),
        })

    def _register_intrusion(self, ts: int, zone_id, camera_id):
        self._intrusions.append((ts, zone_id, camera_id))
        for entry in self._pending_risk:
            if ts >= entry["ts_from"] and _same_place(zone_id, camera_id, entry["zone_id"], entry["camera_id"]):
                entry["intrusion"] = True

    def _on_process(self, event: Dict) -> List[Dict[str, Any]]:
        p = event.get("payload") or {}
        decision = self._decision(p, "PROCESS_EVENT_CONFIRMED")
        if decision != "PROCESS_EVENT_CONFIRMED":
            self._suppress(event, decision)
            return []
        raw_type = str(p.get("process_event_type") or "")
        ptype = PROCESS_TYPES.get(raw_type.lower(), raw_type)
        employee_id = _employee_of(event, p)
        if ptype == "food_handoff":
            self._mark_handoff(event, employee_id)
        payload = self._process_payload(
            ptype, employee_id, p.get("zone_id"), event.get("camera_id"),
            _ms(event.get("timestamp")), p.get("details") or {}, self._provenance(event),
        )
        payload["process_event_id"] = p.get("process_event_id") or event.get("event_id") or payload["process_event_id"]
        out = self._ship(payload)
        if out and self.cfg["clip_for_process_event"]:
            out += self._clip(event, "process_event_id", payload["process_event_id"])
        return out

    def _mark_handoff(self, event: Dict, employee_id: Optional[str]):
        lineage = event.get("track_lineage_id")
        for entry in self._pending_risk:
            if entry["carrying_type"] != "food" or entry["camera_id"] != event.get("camera_id"):
                continue
            if ((lineage and entry["lineage"] == lineage)
                    or (employee_id and entry["employee_id"] == employee_id)
                    or not (lineage or employee_id)):
                entry["handoff"] = True

    def _on_data_quality(self, event: Dict) -> List[Dict[str, Any]]:
        p = event.get("payload") or {}
        decision = self._decision(p, "DATA_QUALITY_EVENT_CONFIRMED")
        if decision != "DATA_QUALITY_EVENT_CONFIRMED":
            self._suppress(event, decision)
            return []
        observation_state = self._obs_state(event, p)
        payload = {
            "event_type": "DATA_QUALITY_EVENT",
            "data_quality_event_id": p.get("data_quality_event_id") or event.get("event_id") or str(uuid.uuid4()),
            "reason": p.get("reason"),
            "action_id": p.get("action_id"),
            "employee_id": _employee_of(event, p),
            "observation_state": observation_state,
            "suppressed_events": [str(x) for x in (p.get("suppressed_events") or [])],
            "zone_id": p.get("zone_id"),
            "camera_id": event.get("camera_id"),
            "timestamp": _ms(event.get("timestamp")),
            "raw_payload": self._provenance(event),
        }
        out = self._ship(payload)
        if out and observation_state == "OBS_LOST" and self.cfg["clip_for_data_quality_obs_lost"]:
            out += self._clip(event, "data_quality_event_id", payload["data_quality_event_id"])
        return out

    def _on_passthrough(self, event: Dict) -> List[Dict[str, Any]]:
        out_type = PASSTHROUGH[str(event["event_type"]).lower()]
        payload = dict(event.get("payload") or {})
        payload["event_type"] = out_type
        payload.setdefault(ID_FIELD[out_type], event.get("event_id") or str(uuid.uuid4()))
        payload.setdefault("camera_id", event.get("camera_id"))
        if out_type != "AUDIT_CLIP":
            payload.setdefault("raw_payload", self._provenance(event))
        return self._ship(payload)

    def _gc(self, now: float):
        if now - self._last_gc < 5.0:
            return
        self._last_gc = now
        ttl = self.cfg["state_ttl_sec"]
        resume = self.cfg["T_resume_interrupt_sec"]
        self._actions = {k: v for k, v in self._actions.items() if now - v["seen"] <= ttl}
        self._left_zone = {k: v for k, v in self._left_zone.items() if now - v["seen"] <= resume}
        cutoff = int(time.time() * 1000) - int(ttl * 1000)
        self._violation_last = {k: v for k, v in self._violation_last.items() if v >= cutoff}
        while self._intrusions and self._intrusions[0][0] < cutoff:
            self._intrusions.popleft()

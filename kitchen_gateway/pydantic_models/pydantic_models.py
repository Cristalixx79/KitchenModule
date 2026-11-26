from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Константы — lower_snake_case
# ---------------------------------------------------------------------------

SANITARY_EVENT_TYPES = [
    "incompatible_transition_detected",
    "left_zone_with_tool",
    "right_zone_with_tool",
    "intrusion_work_zone",
    "no_cap",
    "no_gloves",
    "no_apron",
    "face_touch",
    "phone_usage",
    "food_consumption_in_work_zone",
    "food_consumption_after_handling",
    "drinking_in_work_zone",
    "alcohol_consumption_in_work_zone",
    "smoking_in_work_zone",
    "mouth_contact_with_hands_or_objects_in_work_zone",
]

SEVERITY_INNER_LEVELS = [
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "warning",
    "violation",
]

SEVERITY_LEVELS = ["info", "warning", "violation"]

ESCALATION_LEVELS = [
    "alcohol_escalation",
    "smoking_escalation",
]

INCOMPATIBILITY_CAUSES = [
    "missing_hands_washed",
    "missing_gloves_change",
    "missing_surface_sanitized",
    "missing_tool_reset",
    "missing_container_reset",
    "forbidden_zone_transition",
    "contaminated_source_contact",
    "unknown_source_state",
    "behavioral_block_active",
]

FINAL_DECISIONS = [
    "sanitary_violation_confirmed",
    "process_event_confirmed",
    "unresolved_due_to_data_quality",
    "data_quality_event_confirmed",
    "no_event",
]

OBSERVATION_STATES = [
    "obs_ok",
    "obs_weak",
    "obs_degraded",
    "obs_lost",
]

PROCESS_EVENT_TYPES = [
    "food_handoff",
    "action_interruption",
    "zone_risk_score",
]

END_REASONS = [
    "tracking_lost",
    "left_zone",
    "key_object_lost",
    "motion_stopped",
]

CARRYING_TYPES = [
    "none",
    "food",
    "tool",
]

SEVERITY_VIOLATION = ["violation", "high", "critical"]
SEVERITY_WARNING = ["warning", "low", "medium"]
SEVERITY_INFO = ["info"]


class BaseEventLn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    restaurant_id: int = Field(ge=0)
    occurred_at: datetime
    camera_id: str


class HandsState(BaseModel):
    state: str
    confidence: float = Field(ge=0.0, le=1.0)


class SurfaceState(BaseModel):
    state: str
    confidence: float = Field(ge=0.0, le=1.0)


class ActionEventLn(BaseEventLn):
    action_id: uuid.UUID
    employee_id: Optional[int] = Field(default=None, ge=0)
    action_type: str
    object_class: str = ""
    zone_id: Optional[str] = None
    started_at: datetime
    ended_at: datetime
    end_reason: str
    carrying_type: str = "none"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    model_versions: Dict[str, str] = Field(default_factory=dict)

    @field_validator("end_reason", mode="before")
    @classmethod
    def validate_end_reason(cls, v: Any) -> str:
        if v in END_REASONS:
            return str(v)
        raise ValueError(f"end_reason must be one of {END_REASONS}")

    @field_validator("carrying_type", mode="before")
    @classmethod
    def validate_carrying_type(cls, v: Any) -> str:
        if v in CARRYING_TYPES:
            return str(v)
        raise ValueError(f"carrying_type must be one of {CARRYING_TYPES}")


class HygieneCheckLn(BaseEventLn):
    check_id: uuid.UUID
    action_id: uuid.UUID
    employee_id: Optional[int] = Field(default=None, ge=0)
    zone_id: Optional[str] = None
    hands: HandsState
    surface: SurfaceState
    decision_status: str
    decision_confidence: float = Field(ge=0.0, le=1.0)
    latency_total_ms: float = Field(ge=0.0)


class SanitaryEventLn(BaseEventLn):
    event_id: uuid.UUID
    employee_id: Optional[int] = Field(default=None, ge=0)
    event_type: str
    zone_id: Optional[str] = None
    severity: str
    severity_internal: str
    escalation_category: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_type", mode="before")
    @classmethod
    def validate_sanitary_event_type(cls, v: Any) -> str:
        if v in SANITARY_EVENT_TYPES:
            return str(v)
        raise ValueError(f"event_type must be one of {SANITARY_EVENT_TYPES}")

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v: Any) -> str:
        if v in SEVERITY_LEVELS:
            return str(v)
        raise ValueError(f"severity must be one of {SEVERITY_LEVELS}")

    @field_validator("escalation_category", mode="before")
    @classmethod
    def validate_escalation_category(cls, v: Any) -> Optional[str]:
        if v in (None, ""):
            return None
        if v in ESCALATION_LEVELS:
            return str(v)
        raise ValueError(f"escalation_category must be one of {ESCALATION_LEVELS}")

    @model_validator(mode="after")
    def map_severity_internal(self) -> "SanitaryEventLn":
        # Здесь была ошибка: warning проверялся по SEVERITY_VIOLATION.
        if self.severity_internal in SEVERITY_VIOLATION:
            self.severity = "violation"
        elif self.severity_internal in SEVERITY_WARNING:
            self.severity = "warning"
        elif self.severity_internal in SEVERITY_INFO:
            self.severity = "info"
        else:
            raise ValueError(
                "severity_internal must be in "
                f"{SEVERITY_VIOLATION + SEVERITY_WARNING + SEVERITY_INFO}"
            )
        return self


class ProcessEventLn(BaseEventLn):
    event_id: uuid.UUID
    event_type: str
    action_id: Optional[uuid.UUID] = None
    employee_id: Optional[int] = Field(default=None, ge=0)
    zone_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_type", mode="before")
    @classmethod
    def validate_process_event_type(cls, v: Any) -> str:
        if v in PROCESS_EVENT_TYPES:
            return str(v)
        raise ValueError(f"event_type must be one of {PROCESS_EVENT_TYPES}")


class DataQualityEventLn(BaseEventLn):
    event_id: uuid.UUID
    reason: str
    zone_id: Optional[str] = None          # ← добавлено
    action_id: Optional[uuid.UUID] = None
    employee_id: Optional[int] = Field(default=None, ge=0)
    observation_state: Optional[str] = None
    suppressed_events: list[str] = Field(default_factory=list)

    @field_validator("observation_state", mode="before")
    @classmethod
    def validate_observation_state(cls, v: Any) -> Optional[str]:
        if v in (None, ""):
            return None
        if v in OBSERVATION_STATES:
            return str(v)
        raise ValueError(f"observation_state must be one of {OBSERVATION_STATES}")


class EnvironmentStateLn(BaseEventLn):
    state_id: uuid.UUID
    zone_id: Optional[str] = None
    status: str
    surface_dirty_score: float = Field(ge=0.0, le=1.0)
    contact_zone_dirty_score: float = Field(ge=0.0, le=1.0)
    trash_score: float = Field(ge=0.0, le=1.0)
    contamination_score: float = Field(ge=0.0, le=1.0)
    open_container_detected: bool


class AuditClipLn(BaseEventLn):
    clip_id: uuid.UUID
    storage_ref: str
    duration_seconds: float = Field(ge=0.0)
    retention_until: datetime
    sanitary_event_id: Optional[uuid.UUID] = None
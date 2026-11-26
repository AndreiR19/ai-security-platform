from typing import Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    model_validator,
)

from src.ingestion.models import AuthEvent

MAX_EVIDENCE_EVENTS = 10


class Alert(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str
    severity: Literal["low", "medium", "high", "critical"]
    mitre_technique: str
    source_ip: IPvAnyAddress
    username: str | None = None
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    evidence: tuple[AuthEvent, ...] = Field(min_length=1, max_length=MAX_EVIDENCE_EVENTS)
    event_count: int = Field(ge=1)

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        if len(self.evidence) != min(self.event_count, MAX_EVIDENCE_EVENTS):
            raise ValueError("evidence length must equal min(event_count, MAX_EVIDENCE_EVENTS)")
        if self.first_seen > self.last_seen:
            raise ValueError("first_seen must not be after last_seen")
        return self

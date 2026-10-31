from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, IPvAnyAddress

from src.ingestion.models import AuthEvent


class Alert(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str
    severity: Literal["low", "medium", "high", "critical"]
    mitre_technique: str
    source_ip: IPvAnyAddress
    username: str | None = None
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    evidence: tuple[AuthEvent, ...] = Field(min_length=1)
"""Shared data types for OSINT lookups. Pydantic for serialisation, dataclasses for hot paths."""
from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class QueryKind(StrEnum):
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    TELEGRAM = "telegram"
    WHATSAPP = "whatsapp"
    IP = "ip"
    DOMAIN = "domain"


class HitStatus(StrEnum):
    FOUND = "found"           # account/profile exists
    NOT_FOUND = "not_found"   # confirmed absent
    UNCERTAIN = "uncertain"   # ambiguous response (often soft block / rate-limited)
    ERROR = "error"           # network/HTTP error
    RATELIMITED = "ratelimited"
    SKIPPED = "skipped"       # disabled, missing creds, etc.


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Hit(BaseModel):
    """A single OSINT finding. One Hit per (module, site/source) pair."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    module: str
    source: str                       # e.g. "github.com", "hibp", "telegram"
    category: str = ""                # e.g. "social", "breach", "messaging"
    status: HitStatus
    title: str = ""
    url: str = ""
    detail: str = ""                  # short human description
    extra: dict[str, Any] = Field(default_factory=dict)
    severity: Severity = Severity.INFO
    found_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    latency_ms: int = 0

    @property
    def is_positive(self) -> bool:
        return self.status == HitStatus.FOUND


class Query(BaseModel):
    """A single user-issued query. Kinds are dispatched to one or more modules."""

    model_config = ConfigDict(extra="ignore")

    kind: QueryKind
    value: str                        # the input string (username, email, phone…)
    note: str = ""
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class QueryResult(BaseModel):
    """Aggregate of all hits for a single query."""

    model_config = ConfigDict(extra="ignore")

    query: Query
    hits: list[Hit] = Field(default_factory=list)
    finished_at: datetime | None = None
    duration_ms: int = 0

    @property
    def positives(self) -> list[Hit]:
        return [h for h in self.hits if h.is_positive]

    @property
    def errors(self) -> list[Hit]:
        return [h for h in self.hits if h.status == HitStatus.ERROR]

    @property
    def total(self) -> int:
        return len(self.hits)

    @property
    def found(self) -> int:
        return len(self.positives)

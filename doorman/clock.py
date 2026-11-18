"""Single source of time, so tests can move the clock."""

from datetime import datetime, timedelta, timezone

_offset = timedelta(0)


def now() -> datetime:
    return datetime.now(timezone.utc) + _offset


def iso(dt: datetime | None = None) -> str:
    return (dt or now()).astimezone(timezone.utc).isoformat(timespec="seconds")


def parse(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def advance(seconds: float) -> None:
    """Move the clock forward (tests only)."""
    global _offset
    _offset += timedelta(seconds=seconds)


def reset() -> None:
    global _offset
    _offset = timedelta(0)

from __future__ import annotations

from abc import ABC, abstractmethod
from threading import Lock


class ReplayStore(ABC):
    """
    Credential-scoped storage used to prevent TOTP replay attacks.

    Implementations must make :meth:`consume` atomic. The method is called
    with the timecode of a successfully matched OTP and must return ``True``
    only when that timecode had not been consumed before. Implementations may
    additionally reject timecodes older than the last accepted one. A shared
    database can implement this with a single conditional insert or update,
    so all application workers observe the same state.

    A store instance represents one credential's state. Use a separate store
    (or a credential-scoped adapter over a shared database) for each account.
    """

    @abstractmethod
    def consume(self, timecode: int) -> bool:
        """
        Atomically record ``timecode`` as consumed.

        :param timecode: the matching TOTP timecode
        :returns: ``True`` if the timecode was newly consumed, ``False`` if it was already used
        """


class TOTPSerializer(ABC):
    """
    Persistence interface for the last accepted TOTP timecode.

    This mirrors the serializer interface suggested for PyOTP: it stores a
    single high-water mark rather than every accepted timecode. Implementations
    must make the read/compare/write sequence in :class:`ReplayStore` atomic;
    otherwise two concurrent requests can both accept the same timecode.
    """

    @abstractmethod
    def get_last_used_totp_timestamp(self) -> int | None:
        """Return the last accepted timecode, or ``None`` if no OTP was accepted yet."""

    @abstractmethod
    def save_last_used_totp_timestamp(self, timestamp: int) -> None:
        """Persist the last accepted timecode."""


class InMemoryReplayStore(ReplayStore):
    """
    Thread-safe, process-local replay store.

    This implementation is suitable for a single application process. It does
    not protect against replay across multiple processes or hosts; use a shared
    database-backed :class:`ReplayStore` in multi-instance deployments.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._consumed_timecodes: set[int] = set()
        self._last_timecode: int | None = None

    def consume(self, timecode: int) -> bool:
        with self._lock:
            if timecode in self._consumed_timecodes:
                return False
            self._consumed_timecodes.add(timecode)
            if self._last_timecode is None or timecode > self._last_timecode:
                self._last_timecode = timecode
            return True

    @property
    def last_consumed_timecode(self) -> int | None:
        """The highest consumed timecode, or ``None`` if none has been consumed."""
        with self._lock:
            return self._last_timecode

    def is_consumed(self, timecode: int) -> bool:
        """Return whether ``timecode`` has already been consumed."""
        with self._lock:
            return timecode in self._consumed_timecodes


class _SerializerReplayStore(ReplayStore):
    def __init__(self, serializer: TOTPSerializer) -> None:
        self._serializer = serializer

    def consume(self, timecode: int) -> bool:
        last_timecode = self._serializer.get_last_used_totp_timestamp()
        if last_timecode is not None and timecode <= last_timecode:
            return False
        self._serializer.save_last_used_totp_timestamp(timecode)
        return True

from __future__ import annotations

import threading
from typing import Protocol, runtime_checkable


@runtime_checkable
class UsedTimecodeStore(Protocol):
    """
    Storage backend for TOTP replay protection.

    Implementations record which timecodes have already been consumed for
    each account. :meth:`consume` must be atomic: two concurrent calls for
    the same account and timecode must not both succeed. The in-memory
    implementation below is safe for threads within one process; deployments
    spanning multiple processes or hosts need a shared backend (for example
    one backed by Redis or a SQL database).
    """

    def consume(self, key: str, timecode: int) -> bool:
        """
        Atomically mark ``timecode`` as used for ``key``.

        :returns: True if the timecode was newly recorded, False if it had
            already been consumed
        """
        ...


class InMemoryUsedTimecodeStore:
    """
    Process-local :class:`UsedTimecodeStore` backed by a dict.

    Thread-safe, but not shared across processes. Entries are kept for the
    lifetime of the store, one per successful verification.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._used: dict[str, set[int]] = {}

    def consume(self, key: str, timecode: int) -> bool:
        with self._lock:
            used = self._used.setdefault(key, set())
            if timecode in used:
                return False
            used.add(timecode)
            return True

    def clear(self) -> None:
        """Forget all recorded timecodes for all accounts."""
        with self._lock:
            self._used.clear()


shared_store = InMemoryUsedTimecodeStore()

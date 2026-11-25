from __future__ import annotations

import calendar
import datetime
import hashlib
import time
from typing import Any

from . import utils
from .exceptions import OTPVerificationError
from .otp import OTP
from .replay import ReplayStore, TOTPSerializer, _SerializerReplayStore

_TIMESTAMP_LIMIT = 253402300800  # 10000-01-01 00:00:00 UTC, exclusive.


class TOTP(OTP):
    """
    Handler for time-based OTP counters.
    """

    def __init__(
        self,
        s: str,
        *,
        digits: int = 6,
        digest: Any = None,
        name: str | None = None,
        issuer: str | None = None,
        interval: int = 30,
        replay_store: ReplayStore | None = None,
        serializer: TOTPSerializer | None = None,
        store: ReplayStore | None = None,
    ) -> None:
        """
        :param s: secret in base32 format
        :param digits: number of digits in the OTP, from 6 to 10
        :param digest: digest function to use in the HMAC (expected to be SHA1)
        :param name: account name
        :param issuer: issuer
        :param interval: the time interval in seconds, greater than 0 and at most 120. Defaults to 30.
        :param replay_store: optional credential-scoped store used to consume matching timecodes
        :param serializer: optional persistence interface for the last accepted timecode
        :param store: alias for ``replay_store``

        See `NIST SP 800-63B-4 section 3.1.4.1
        <https://pages.nist.gov/800-63-4/sp800-63b.html>`_.
        """
        if digest is None:
            digest = hashlib.sha1
        elif digest in [hashlib.md5, hashlib.shake_128]:
            raise ValueError("selected digest function must generate digest size greater than or equals to 18 bytes")

        # NIST SP 800-63B-4 section 3.1.4.1 requires a new nonce at least every two minutes.
        if not 0 < interval <= 120:
            raise ValueError("interval must be positive and at most 120 seconds")
        self.interval = interval
        if store is not None:
            if replay_store is not None:
                raise TypeError("specify only one of replay_store and store")
            replay_store = store
        if replay_store is not None and serializer is not None:
            raise TypeError("specify only one of replay_store and serializer")
        if replay_store is None and serializer is not None:
            replay_store = _SerializerReplayStore(serializer)
        self.replay_store = replay_store
        self.serializer = serializer
        super().__init__(s=s, digits=digits, digest=digest, name=name, issuer=issuer)

    def at(self, for_time: int | float | datetime.datetime, *, counter_offset: int = 0) -> str:
        """
        Accepts a Unix timestamp (int or float) or a datetime object.

        Unix timestamps are measured in seconds since 1970-01-01 00:00:00 UTC.
        Prefer Unix timestamps or timezone-aware UTC datetimes. Naive
        datetimes are interpreted as local time, respecting ``fold``.

        To get the time until the next timecode change (seconds until the current OTP expires), use this instead:

        .. code:: python

            totp = pyotp.TOTP(...)
            time_remaining = totp.interval - time.time() % totp.interval

        :param for_time: the time to generate an OTP for
        :param counter_offset: the amount of ticks to add to the time counter
        :returns: OTP value
        :raises ValueError: if for_time is before the Unix epoch or after year 9999 in UTC
        """
        return self.generate_otp(self.timecode(for_time) + counter_offset)

    def now(self) -> str:
        """
        Generate the current time OTP

        :returns: OTP value
        :raises ValueError: if the current time is before the Unix epoch or after year 9999 in UTC
        """
        return self.generate_otp(self.timecode(time.time()))

    def verify(
        self,
        otp: str,
        *,
        for_time: int | float | datetime.datetime | None = None,
        valid_window: int = 0,
        replay_store: ReplayStore | None = None,
        store: ReplayStore | None = None,
    ) -> bool:
        """
        Verifies the OTP passed in against the current time OTP.

        Unix timestamps are measured in seconds since 1970-01-01 00:00:00 UTC.
        Prefer Unix timestamps or timezone-aware UTC datetimes. Naive
        datetimes are interpreted as local time, respecting ``fold``.

        :param otp: the OTP to check against
        :param for_time: Unix timestamp (int or float) or datetime to check OTP at (defaults to now)
        :param valid_window: extends the validity to this many counter ticks before and after the current one
        :param replay_store: optional credential-scoped store used to consume the matching timecode
        :param store: alias for ``replay_store``
        :returns: True if verification succeeded, False otherwise
        :raises ValueError: if for_time is before the Unix epoch or after year 9999 in UTC
        """
        if for_time is None:
            for_time = time.time()

        resolved_store = self._resolve_replay_store(replay_store, store)
        return self._verify_timecode(otp, for_time, valid_window, resolved_store) is not None

    def verify_and_get_timecode(
        self,
        otp: str,
        *,
        for_time: int | float | datetime.datetime | None = None,
        valid_window: int = 0,
        replay_store: ReplayStore | None = None,
        store: ReplayStore | None = None,
    ) -> int:
        """
        Verifies the OTP passed in against the current time OTP and returns the matching timecode.

        .. caution::

            Note the signature difference between this method and :meth:`verify`:
            this method raises :class:`~pyotp.exceptions.OTPVerificationError`
            on an OTP mismatch, while :meth:`verify` returns ``False``.

        This is useful when callers need to prevent TOTP reuse. An
        application can store the timecode from the last successful
        authentication and reject future OTPs whose matching timecode
        is not greater than the stored one.

        Unix timestamps are measured in seconds since 1970-01-01 00:00:00 UTC.
        Prefer Unix timestamps or timezone-aware UTC datetimes. Naive
        datetimes are interpreted as local time, respecting ``fold``.

        :param otp: the OTP to check against
        :param for_time: Unix timestamp (int or float) or datetime to check OTP at (defaults to now)
        :param valid_window: extends the validity to this counter ticks before and after the current one
        :param replay_store: optional credential-scoped store used to consume the matching timecode
        :param store: alias for ``replay_store``
        :returns: matching timecode if verification succeeded
        :raises pyotp.exceptions.OTPVerificationError: if the OTP does not match within the valid window
        :raises ValueError: if valid_window is negative or for_time is before the Unix epoch or after year 9999 in UTC
        """
        if for_time is None:
            for_time = time.time()

        if valid_window < 0:
            raise ValueError("valid_window cannot be negative")

        resolved_store = self._resolve_replay_store(replay_store, store)
        matched_timecode = self._verify_timecode(otp, for_time, valid_window, resolved_store)
        if matched_timecode is not None:
            return matched_timecode
        raise OTPVerificationError("OTP verification failed")

    def _resolve_replay_store(self, replay_store: ReplayStore | None, store: ReplayStore | None) -> ReplayStore | None:
        if replay_store is not None and store is not None:
            raise TypeError("specify only one of replay_store and store")
        resolved_store = replay_store if replay_store is not None else store
        return self.replay_store if resolved_store is None else resolved_store

    def _verify_timecode(
        self,
        otp: str,
        for_time: int | float | datetime.datetime,
        valid_window: int,
        replay_store: ReplayStore | None,
    ) -> int | None:
        timecode = self.timecode(for_time)
        offsets = range(-valid_window, valid_window + 1) if valid_window else (0,)
        for offset in offsets:
            candidate_timecode = timecode + offset
            if utils.strings_equal(str(otp), str(self.generate_otp(candidate_timecode))):
                if replay_store is None or replay_store.consume(candidate_timecode):
                    return candidate_timecode
        return None

    def provisioning_uri(self, *, name: str | None = None, issuer_name: str | None = None, **kwargs: Any) -> str:
        """
        Returns the provisioning URI for the OTP.  This can then be
        encoded in a QR Code and used to provision an OTP app like
        Google Authenticator.

        See also:
            https://github.com/google/google-authenticator/wiki/Key-Uri-Format

        """
        return utils.build_uri(
            self.secret,
            name if name else self.name,
            issuer=issuer_name if issuer_name else self.issuer,
            algorithm=self.digest().name,
            digits=self.digits,
            period=self.interval,
            **kwargs,
        )

    def timecode(self, for_time: int | float | datetime.datetime) -> int:
        """
        Converts a Unix timestamp (int or float) or a datetime object
        to the corresponding counter value (timecode).

        Unix timestamps are measured in seconds since 1970-01-01 00:00:00 UTC.
        Prefer Unix timestamps or timezone-aware UTC datetimes. Naive
        datetimes are interpreted as local time, using ``fold`` to
        distinguish repeated clock times. Subsecond precision is ignored.

        :raises ValueError: if for_time is before the Unix epoch or after year 9999 in UTC
        """
        error_message = "for_time must be at or after the Unix epoch and before year 10000 UTC"
        timestamp: int | float
        if isinstance(for_time, datetime.datetime):
            try:
                if for_time.tzinfo:
                    timestamp = calendar.timegm(for_time.utctimetuple())
                else:
                    # Preserve whole-second behavior without discarding fold.
                    timestamp = for_time.replace(microsecond=0).timestamp()
            except (OverflowError, OSError, ValueError) as error:
                raise ValueError(error_message) from error
        else:
            timestamp = for_time
        if not 0 <= timestamp < _TIMESTAMP_LIMIT:
            raise ValueError(error_message)
        return int(int(timestamp) / self.interval)

from __future__ import annotations

import hashlib
from typing import Any

from . import utils
from .exceptions import OTPVerificationError
from .otp import OTP


class HOTP(OTP):
    """
    Handler for HMAC-based OTP counters.
    """

    def __init__(
        self,
        s: str,
        *,
        digits: int = 6,
        digest: Any = None,
        name: str | None = None,
        issuer: str | None = None,
        initial_count: int = 0,
    ) -> None:
        """
        :param s: secret in base32 format
        :param initial_count: starting HMAC counter value, defaults to 0
        :param digits: number of digits in the OTP, from 6 to 10
        :param digest: digest function to use in the HMAC (expected to be SHA1)
        :param name: account name
        :param issuer: issuer
        """
        if digest is None:
            digest = hashlib.sha1
        elif digest in [hashlib.md5, hashlib.shake_128]:
            raise ValueError("selected digest function must generate digest size greater than or equals to 18 bytes")

        self.initial_count = initial_count
        # Counter state machine. The consumed watermark, the hit offset of the
        # most recent successful verification, and the resync target are
        # maintained together by verify_and_get_counter().
        self._consumed_counter = -1
        self._last_hit_offset: int | None = None
        self._resync_target = 0
        super().__init__(s=s, digits=digits, digest=digest, name=name, issuer=issuer)

    @property
    def consumed_counter(self) -> int:
        """
        The consumed watermark: the highest counter consumed by a successful
        verification, or -1 if no OTP has been accepted yet. Counters at or
        below this value are rejected by :meth:`verify_and_get_counter`.
        """
        return self._consumed_counter

    @property
    def last_hit_offset(self) -> int | None:
        """
        The offset of the most recent hit within the searched window, or None
        if no OTP has been accepted yet.
        """
        return self._last_hit_offset

    @property
    def resync_target(self) -> int:
        """
        The counter the next stateful verification resumes from: one past the
        last consumed counter.
        """
        return self._resync_target

    def at(self, count: int) -> str:
        """
        Generates the OTP for the given count.

        :param count: the OTP HMAC counter
        :returns: OTP
        """
        return self.generate_otp(self.initial_count + count)

    def verify(self, otp: str, counter: int) -> bool:
        """
        Verifies the OTP passed in against the current counter OTP.

        This check is stateless: it does not advance the counter state
        machine and does not by itself prevent OTP reuse. Use
        :meth:`verify_and_get_counter` to consume counters and reject
        replayed OTPs.

        :param otp: the OTP to check against
        :param counter: the OTP HMAC counter
        """
        return utils.strings_equal(str(otp), str(self.at(counter)))

    def verify_and_get_counter(self, otp: str, counter: int | None = None, valid_window: int = 0) -> int:
        """
        Verifies the OTP passed in against the counter window and advances the
        counter state machine.

        .. caution::

            Note the signature difference between this method and :meth:`verify`:
            this method raises :class:`~pyotp.exceptions.OTPVerificationError`
            on an OTP mismatch, while :meth:`verify` returns ``False``.

        The counter is a state machine built from three quantities maintained
        together: the consumed watermark (:attr:`consumed_counter`), the hit
        offset of this verification (:attr:`last_hit_offset`), and the resync
        target (:attr:`resync_target`). A successful verification consumes the
        matching counter: the watermark moves to the hit counter, the hit
        offset records where in the window the match landed, and the resync
        target moves to one past the hit. Later calls only consider counters
        above the watermark, so an already-accepted OTP is rejected on replay.

        :param otp: the OTP to check against
        :param counter: the first counter to check, defaults to the resync target
        :param valid_window: extends the look-ahead to this many counters after the first one
        :returns: matching counter if verification succeeded
        :raises pyotp.exceptions.OTPVerificationError: if the OTP does not match within the valid window
        :raises ValueError: if valid_window is negative
        """
        if valid_window < 0:
            raise ValueError("valid_window cannot be negative")

        start = self._resync_target if counter is None else counter
        start = max(start, self._consumed_counter + 1)

        for offset in range(valid_window + 1):
            if utils.strings_equal(str(otp), str(self.at(start + offset))):
                self._consumed_counter = start + offset
                self._last_hit_offset = offset
                self._resync_target = start + offset + 1
                return start + offset
        raise OTPVerificationError("OTP verification failed")

    def provisioning_uri(
        self,
        *,
        name: str | None = None,
        initial_count: int | None = None,
        issuer_name: str | None = None,
        **kwargs: Any,
    ) -> str:
        """
        Returns the provisioning URI for the OTP.  This can then be
        encoded in a QR Code and used to provision an OTP app like
        Google Authenticator.

        See also:
            https://github.com/google/google-authenticator/wiki/Key-Uri-Format

        :param name: name of the user account
        :param initial_count: starting HMAC counter value, defaults to 0
        :param issuer_name: the name of the OTP issuer; this will be the
            organization title of the OTP entry in Authenticator
        :returns: provisioning URI
        """
        return utils.build_uri(
            self.secret,
            name=name if name else self.name,
            initial_count=initial_count if initial_count is not None else self.initial_count,
            issuer=issuer_name if issuer_name else self.issuer,
            algorithm=self.digest().name,
            digits=self.digits,
            **kwargs,
        )

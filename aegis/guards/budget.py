from __future__ import annotations

from ..decision import Verdict
from ..grant import Grant
from .base import Call


class BudgetGuard:
    """Pre-flight budget admission control.

    Checks the whole ancestor chain, so N children cannot collectively exceed
    the root's limit even though each is individually within its own.
    """

    name = "budget"

    def check(self, grant: Grant, call: Call) -> Verdict:
        return grant.ledger.check(
            usd=call.est_usd, tokens=call.est_tokens, calls=1)

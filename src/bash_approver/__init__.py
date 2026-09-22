"""bash_approver: the decision engine behind hooks/bash-approver.py.

The hook is a thin entry point. Everything it decides lives here, split by the question
each part answers:

    segmentation    where does one command end and the next begin, and what did the
                    shell do to the text before any of it ran
    command_model   given one segment, what is actually about to execute once
                    env-assignments, wrappers and sudo are stripped off the front
    destructive     is this catastrophic, regardless of what any safe-list says
    policy          allow, ask or deny, and the promotion envelope that bounds what an
                    optional local model is even permitted to upgrade
    model_promoter  the optional local model itself, fail-closed
    decision_log    append-only telemetry for tuning

SECURITY MODEL, unchanged by the split: a wrong ALLOW is the only unacceptable outcome.
A wrong ASK is friction. Every ambiguity collapses toward ASK.
"""
from .policy import (
    DECISION_ALLOW,
    DECISION_ASK,
    DECISION_DENY,
    decide,
    promotable,
)

__all__ = [
    "DECISION_ALLOW",
    "DECISION_ASK",
    "DECISION_DENY",
    "decide",
    "promotable",
]

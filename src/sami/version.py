"""Version of the analysis layer, recorded in every report and custody entry."""

__version__ = "0.1.0"

#: Bumped when a rule's *meaning* changes, so a stored report can be traced to
#: the rule semantics that produced it even after thresholds move.
RULESET_VERSION = 1

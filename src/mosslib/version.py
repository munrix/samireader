"""Single source of truth for the version reported in every report and log entry."""

__version__ = "0.1.0"

#: Bumped whenever the log grammar in :mod:`mosslib.grammar` changes in a way
#: that could alter a parse result. Recorded in every report and every golden
#: file so a stored result can always be traced to the grammar that produced it.
GRAMMAR_VERSION = 1

#: MOSS versions the grammar has been exercised against. Parsing a version
#: outside this set still works (the parser is tolerant) but raises an
#: informational warning so reports can say so out loud.
KNOWN_MOSS_VERSIONS = ("6.6.9.0",)

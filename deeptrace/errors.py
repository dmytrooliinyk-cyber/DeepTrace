class DeepTraceError(Exception):
    """An expected, user-facing DeepTrace error."""


class ParseError(DeepTraceError):
    """Input bytes are malformed, truncated, or unsupported."""


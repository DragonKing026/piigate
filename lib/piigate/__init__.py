"""piigate — filters sensitive data (PHI/PII) before it reaches the model's context.

Python standard library only (the hook starts on every Read/Bash) + `pdftotext` (poppler).
"""


class FilterError(Exception):
    """The filter cannot process the data safely — the caller must deny (never pass the original through)."""

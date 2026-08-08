"""Provenance compiler exceptions."""


class CompilationError(ValueError):
    """Raised when runtime evidence cannot truthfully form a DBOM receipt."""

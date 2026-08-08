"""Runtime SDK exceptions."""


class GlassBoxRuntimeError(RuntimeError):
    """Base class for runtime instrumentation failures."""


class NoActiveRunError(GlassBoxRuntimeError):
    """Raised when evidence or an action is recorded outside a run."""


class PolicyViolationError(GlassBoxRuntimeError):
    """Raised before a governed action that lacks required controls."""


class TelemetryExportError(GlassBoxRuntimeError):
    """Raised when a fail-closed event cannot reach its configured sink."""


class EvidenceValidationError(GlassBoxRuntimeError):
    """Raised when an evidence state lacks its required proof fields."""


class DuplicateActionError(GlassBoxRuntimeError):
    """Raised when a callback reuses an unfinished external call identifier."""


class UnknownActionError(GlassBoxRuntimeError):
    """Raised when a terminal callback has no matching action start."""

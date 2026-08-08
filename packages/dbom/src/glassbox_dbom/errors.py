"""Typed DBOM failures."""


class DBOMError(Exception):
    """Base exception for a DBOM operation."""


class CanonicalizationError(DBOMError):
    """The value cannot be represented by the canonical JSON profile."""


class SchemaValidationError(DBOMError):
    """A receipt does not satisfy its declared DBOM schema."""

    def __init__(self, errors: tuple[str, ...]) -> None:
        self.errors = errors
        super().__init__("; ".join(errors))


class IntegrityError(DBOMError):
    """A receipt cannot be sealed or its integrity material is malformed."""

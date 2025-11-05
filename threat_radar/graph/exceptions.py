"""Custom exceptions for graph analysis operations."""


class GraphAnalysisError(Exception):
    """Base exception for graph analysis errors."""
    pass


class GraphTraversalError(GraphAnalysisError):
    """Raised when graph traversal fails or exceeds limits."""
    pass


class MalformedGraphError(GraphAnalysisError):
    """Raised when graph structure is invalid or malformed."""
    pass


class InvalidScanResultError(GraphAnalysisError):
    """Raised when scan result data is invalid or malformed."""
    pass


class GraphValidationError(GraphAnalysisError):
    """Raised when graph validation fails."""
    pass


class TraversalLimitExceeded(GraphTraversalError):
    """Raised when traversal exceeds configured limits (DoS prevention)."""
    pass


class TimeoutExceeded(GraphTraversalError):
    """Raised when operation exceeds timeout."""
    pass

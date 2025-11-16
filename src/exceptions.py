"""
Custom exceptions for CodeBadger Toolkit Server
"""


class JoernMCPException(Exception):
    """Base exception for CodeBadger Toolkit"""

    pass


class SessionNotFoundError(JoernMCPException):
    """Session does not exist"""

    pass


class SessionNotReadyError(JoernMCPException):
    """Session is not in ready state"""

    pass


class CPGGenerationError(JoernMCPException):
    """CPG generation failed"""

    pass


class QueryExecutionError(JoernMCPException):
    """Query execution failed"""

    pass


class DockerError(JoernMCPException):
    """Docker operation failed"""

    pass


class ResourceLimitError(JoernMCPException):
    """Resource limit exceeded"""

    pass


class ValidationError(JoernMCPException):
    """Input validation failed"""

    pass


class GitOperationError(JoernMCPException):
    """Git operation failed"""

    pass

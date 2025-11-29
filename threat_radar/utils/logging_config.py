"""Production logging configuration for Threat Radar."""

import logging
import logging.handlers
import json
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime


class JSONFormatter(logging.Formatter):
    """
    Custom JSON formatter for structured logging.
    Outputs logs in JSON format for easy parsing by log aggregation tools.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields if present
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        return json.dumps(log_data)


class ColoredFormatter(logging.Formatter):
    """
    Colored formatter for console output.
    Adds colors to log levels for better readability.
    """

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        level_color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{level_color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logging(
    log_level: str = "INFO",
    log_format: str = "text",
    log_file: Optional[str] = None,
    console_output: bool = True,
    enable_colors: bool = True,
) -> None:
    """
    Configure production logging for Threat Radar.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Output format ('text' or 'json')
        log_file: Path to log file (optional)
        console_output: Enable console output (default: True)
        enable_colors: Enable colored console output (default: True)

    Examples:
        >>> setup_logging(log_level="DEBUG", log_format="json")
        >>> setup_logging(log_level="INFO", log_file="/app/logs/app.log")
    """
    # Convert log level string to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)

        if log_format == "json":
            console_formatter = JSONFormatter()
        else:
            if enable_colors and sys.stdout.isatty():
                console_formatter = ColoredFormatter(
                    "%(asctime)s - %(levelname)s - %(name)s - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            else:
                console_formatter = logging.Formatter(
                    "%(asctime)s - %(levelname)s - %(name)s - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )

        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    # File handler with rotation
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Rotating file handler (max 100MB per file, keep 10 backups)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=100 * 1024 * 1024,  # 100 MB
            backupCount=10,
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)

        # Always use JSON format for file logs (better for log aggregation)
        file_formatter = JSONFormatter()
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    # Separate error log file
    if log_file:
        error_log_path = log_path.parent / "error.log"
        error_handler = logging.handlers.RotatingFileHandler(
            str(error_log_path),
            maxBytes=100 * 1024 * 1024,  # 100 MB
            backupCount=10,
            encoding="utf-8",
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(error_handler)

    # Scan operations log file
    if log_file:
        scan_log_path = log_path.parent / "scan.log"
        scan_handler = logging.handlers.RotatingFileHandler(
            str(scan_log_path),
            maxBytes=100 * 1024 * 1024,  # 100 MB
            backupCount=10,
            encoding="utf-8",
        )
        scan_handler.setLevel(logging.INFO)
        scan_handler.setFormatter(JSONFormatter())

        # Only log from scan-related modules
        scan_logger = logging.getLogger("threat_radar.core.grype_integration")
        scan_logger.addHandler(scan_handler)

        scan_logger2 = logging.getLogger("threat_radar.cli.cve")
        scan_logger2.addHandler(scan_handler)

    # Suppress verbose logs from third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("docker").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("anthropic").setLevel(logging.WARNING)

    # Log initial configuration
    logger = logging.getLogger(__name__)
    logger.info(
        f"Logging configured: level={log_level}, format={log_format}, "
        f"file={log_file if log_file else 'none'}"
    )


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a module.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Logger instance

    Examples:
        >>> logger = get_logger(__name__)
        >>> logger.info("Processing scan results")
    """
    return logging.getLogger(name)


class LogContext:
    """
    Context manager for adding extra fields to log records.

    Examples:
        >>> with LogContext(scan_id="scan-123", image="alpine:3.18"):
        ...     logger.info("Scanning image")
        # Output: {"timestamp": "...", "message": "Scanning image", "scan_id": "scan-123", "image": "alpine:3.18"}
    """

    def __init__(self, **kwargs):
        """Initialize log context with extra fields."""
        self.extra_fields = kwargs
        self.old_factory = None

    def __enter__(self):
        """Enter context and add extra fields to log records."""
        old_factory = logging.getLogRecordFactory()

        def record_factory(*args, **kwargs):
            record = old_factory(*args, **kwargs)
            record.extra_fields = self.extra_fields
            return record

        logging.setLogRecordFactory(record_factory)
        self.old_factory = old_factory
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context and restore original factory."""
        if self.old_factory:
            logging.setLogRecordFactory(self.old_factory)


# Convenience function for common use cases
def setup_production_logging() -> None:
    """
    Setup logging for production deployment.

    Reads configuration from environment variables:
    - LOG_LEVEL: Logging level (default: INFO)
    - LOG_FORMAT: Output format (default: json)
    - LOG_FILE: Log file path (default: /app/logs/app.log)
    """
    import os

    log_level = os.getenv("LOG_LEVEL", "INFO")
    log_format = os.getenv("LOG_FORMAT", "json")
    log_file = os.getenv("LOG_FILE", "/app/logs/app.log")

    setup_logging(
        log_level=log_level,
        log_format=log_format,
        log_file=log_file,
        console_output=True,
        enable_colors=log_format != "json",
    )

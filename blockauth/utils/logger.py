from abc import ABC, abstractmethod
from blockauth.utils.config import get_config

class BaseLogger:
    """
    Base logger interface for Blockauth. Implement this in your project to handle logs from the package.
    """
    @abstractmethod
    def log(self, message: str, context: dict, level: str = 'info', icon=None) -> None:
        """
        Log a message with a given level and optional icon.
        :param message: The log message.
        :param context: Context dictionary (non-sensitive data).
        :param level: Log level (e.g., 'info', 'error', 'success', 'warning').
        :param icon: Optional unicode icon representing the log level.
        """
        raise NotImplementedError("log() must be implemented by subclasses.")


class DummyLogger(BaseLogger):
    """
    Default logger that prints messages to the console.
    Accepts arbitrary keyword arguments to support icon and other future extensions.
    """
    def log(self, message: str, context: dict, level: str = 'info', icon=None, **kwargs) -> None:
        pass


LOG_LEVEL_ICONS = {
    "debug": "🐞",
    "info": "ℹ️",
    "warning": "⚠️",
    "error": "❌",
    "critical": "🔥",
    "exception": "💥",
    "trace": "🔍",
    "notice": "📢",
    "alert": "🚨",
    "fatal": "☠️",
    "success": "✅",
    "pending": "⏳",
}

class BlockAuthLogger:
    """
    BlockAuthLogger provides a unified logging interface for BlocAuth package events.
    
    It attempts to use a custom logger class defined in settings.py as BLOCK_AUTH_LOGGER_CLASS.
    If not configured, all logging methods become no-ops (do nothing).
    
    Usage:
        from blockauth.utils.logger import blockauth_logger
        blockauth_logger.info("User signup", data)
        blockauth_logger.error("Signup failed", error_data)
        blockauth_logger.success("Signup completed", data)
        blockauth_logger.pending("Signup in progress", data)
        blockauth_logger.trace("Trace message", data)
        blockauth_logger.notice("Notice message", data)
        blockauth_logger.alert("Alert message", data)
        blockauth_logger.fatal("Fatal error", data)
    
    The custom logger class must implement a .log(message, data, level, icon) method.
    Supported levels: debug, info, warning, error, critical, exception, trace, notice, alert, fatal, success, pending
    The icon is a unicode symbol representing the log level, provided as the 'icon' argument.
    """
    def __init__(self):
        try:
            logger_class = get_config('BLOCK_AUTH_LOGGER_CLASS')
            if logger_class is None:
                raise ValueError
            self.logger = logger_class()
        except Exception:
            self.logger = None

    def debug(self, message, data=None):
        """Call this to log detailed information, typically of interest only when diagnosing problems."""
        if self.logger:
            self.logger.log(message, data, "debug", icon=LOG_LEVEL_ICONS["debug"])

    def info(self, message, data=None):
        """Call this to log general information about application events (e.g., user actions, process milestones)."""
        if self.logger:
            self.logger.log(message, data, "info", icon=LOG_LEVEL_ICONS["info"])

    def warning(self, message, data=None):
        """Call this to log events that are unusual or unexpected, but not necessarily errors (e.g., deprecated usage, minor issues)."""
        if self.logger:
            self.logger.log(message, data, "warning", icon=LOG_LEVEL_ICONS["warning"])

    def error(self, message, data=None):
        """Call this to log errors that prevent normal program execution, but are not critical system failures."""
        if self.logger:
            self.logger.log(message, data, "error", icon=LOG_LEVEL_ICONS["error"])

    def critical(self, message, data=None):
        """Call this to log very serious errors that may require immediate attention (e.g., system outages, data loss)."""
        if self.logger:
            self.logger.log(message, data, "critical", icon=LOG_LEVEL_ICONS["critical"])

    def exception(self, message, data=None):
        """Call this to log exceptions, typically within an except block, to capture stack traces and error context."""
        if self.logger:
            self.logger.log(message, data, "exception", icon=LOG_LEVEL_ICONS["exception"])

    def trace(self, message, data=None):
        """Call this to log fine-grained tracing information, such as function entry/exit or variable values for debugging."""
        if self.logger:
            self.logger.log(message, data, "trace", icon=LOG_LEVEL_ICONS["trace"])

    def notice(self, message, data=None):
        """Call this to log important but normal events that require special attention (e.g., configuration changes)."""
        if self.logger:
            self.logger.log(message, data, "notice", icon=LOG_LEVEL_ICONS["notice"])

    def alert(self, message, data=None):
        """Call this to log events that require immediate action, but are not yet critical (e.g., nearing resource limits)."""
        if self.logger:
            self.logger.log(message, data, "alert", icon=LOG_LEVEL_ICONS["alert"])

    def fatal(self, message, data=None):
        """Call this to log fatal errors that will lead to application shutdown or unrecoverable failure."""
        if self.logger:
            self.logger.log(message, data, "fatal", icon=LOG_LEVEL_ICONS["fatal"])

    def success(self, message, data=None):
        """Call this to log successful completion of an operation or process (e.g., user registration succeeded)."""
        if self.logger:
            self.logger.log(message, data, "success", icon=LOG_LEVEL_ICONS["success"])

    def pending(self, message, data=None):
        """Call this to log operations that are in progress or waiting for completion (e.g., background job started)."""
        if self.logger:
            self.logger.log(message, data, "pending", icon=LOG_LEVEL_ICONS["pending"])

blockauth_logger = BlockAuthLogger()
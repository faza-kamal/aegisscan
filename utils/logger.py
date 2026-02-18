"""
utils/logger.py
Simple logging wrapper for AegisScan
"""

import logging
import sys


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name (usually module name)
        level: Logging level (default: INFO)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    logger.setLevel(level)
    
    # Console handler with colored output
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    
    # Format: [LEVEL] message
    formatter = logging.Formatter(
        '%(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger


# Default logger instance
log = get_logger("aegisscan")


__all__ = ["get_logger", "log"]

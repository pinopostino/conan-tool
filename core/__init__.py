"""
CONAN Core Module
Contains the fundamental classes for the CONAN Anti-Reversing Detection Framework
"""

from .detection_result import DetectionResult, DetectionResultBuilder, create_result
from .analysis_context import AnalysisContext
from .base_detector import BaseDetector, TaskMonitor
from .detection_engine import DetectionEngine

__all__ = [
    'DetectionResult',
    'DetectionResultBuilder', 
    'create_result',
    'AnalysisContext',
    'BaseDetector',
    'TaskMonitor',
    'DetectionEngine'
]

__version__ = '1.0.0'
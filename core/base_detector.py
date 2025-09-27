"""
CONAN Base Detector - Python Implementation
Translated from Java BaseDetector.java
"""

from abc import ABC, abstractmethod
from typing import Optional, Callable
from .analysis_context import AnalysisContext
from .detection_result import DetectionResultBuilder, create_result


class TaskMonitor:
    """
    Simple task monitor for progress tracking (replaces Ghidra TaskMonitor)
    """
    
    def __init__(self, progress_callback: Optional[Callable[[str, float], None]] = None):
        self.progress_callback = progress_callback
        self.cancelled = False
        self.current_message = ""
        self.current_progress = 0.0
    
    def set_message(self, message: str) -> None:
        """Set current progress message"""
        self.current_message = message
        if self.progress_callback:
            self.progress_callback(message, self.current_progress)
    
    def set_progress(self, progress: float) -> None:
        """Set current progress (0.0 to 1.0)"""
        self.current_progress = max(0.0, min(1.0, progress))
        if self.progress_callback:
            self.progress_callback(self.current_message, self.current_progress)
    
    def is_cancelled(self) -> bool:
        """Check if operation is cancelled"""
        return self.cancelled
    
    def cancel(self) -> None:
        """Cancel the operation"""
        self.cancelled = True
    
    def update_progress(self, message: str, progress: float) -> None:
        """Update both message and progress"""
        self.set_message(message)
        self.set_progress(progress)


class BaseDetector(ABC):
    """
    Abstract base class for all CONAN detectors.
    Provides common functionality and interface for detection modules.
    """
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    def get_name(self) -> str:
        """Get detector name"""
        return self.name
    
    def get_description(self) -> str:
        """Get detector description"""
        return self.description
    
    @abstractmethod
    def analyze(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """
        Perform analysis on the binary.
        Implementations should add results to the context.
        
        Args:
            context: Analysis context containing binary data and results
            monitor: Progress monitor for cancellation and progress updates
        
        Raises:
            Exception: If analysis fails
        """
        pass
    
    def create_result(self) -> DetectionResultBuilder:
        """Create a new DetectionResult builder with detector name pre-filled"""
        return create_result().detector(self.name)
    
    
    def is_valid_address(self, context: AnalysisContext, address: int) -> bool:
        """
        Check if an address is valid within the binary
        
        Args:
            context: Analysis context
            address: Address to check
            
        Returns:
            True if address is valid, False otherwise
        """
        try:
            # Check if address falls within any section
            section = context.get_section_by_address(address)
            return section is not None
        except Exception:
            return False
    
    def is_executable_address(self, context: AnalysisContext, address: int) -> bool:
        """
        Check if an address is in an executable section
        
        Args:
            context: Analysis context
            address: Address to check
            
        Returns:
            True if address is in executable section, False otherwise
        """
        try:
            section = context.get_section_by_address(address)
            return section is not None and section.get('executable', False)
        except Exception:
            return False
    
    def calculate_confidence(self, matches: int, total_checks: int) -> float:
        """
        Calculate confidence score based on matches vs total checks
        
        Args:
            matches: Number of positive matches
            total_checks: Total number of checks performed
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        if total_checks == 0:
            return 0.0
        return matches / total_checks
    
    def log_detection(self, context: AnalysisContext, technique: str, 
                     description: str, address: int, confidence: float = None,
                     evidence: str = None, **metadata) -> None:
        """
        Convenience method to log a detection result
        
        Args:
            context: Analysis context
            technique: Technique name
            description: Description of the detection
            address: Address where detection occurred
            confidence: Confidence score (0.0 to 1.0)
            evidence: Optional evidence string
            **metadata: Additional metadata key-value pairs
        """
        builder = (self.create_result()
                  .technique(technique)
                  .description(description)
                  .address(address))
        
        if confidence is not None:
            builder.confidence(confidence)
        
        if evidence:
            builder.evidence(evidence)
        
        for key, value in metadata.items():
            builder.metadata(key, value)
        
        result = builder.build()
        context.add_result(result)
    
    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.name})"
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name='{self.name}', description='{self.description}')"


# Example concrete detector for testing
class TestDetector(BaseDetector):
    """Simple test detector implementation"""
    
    def __init__(self):
        super().__init__("TestDetector", "A simple test detector")
    
    def analyze(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Test analysis implementation"""
        monitor.set_message("Running test detection...")
        
        # Simulate some work
        import time
        for i in range(5):
            if monitor.is_cancelled():
                return
            
            monitor.update_progress(f"Test step {i+1}/5", (i+1)/5)
            time.sleep(0.1)  # Simulate work
        
        # Add a test result
        self.log_detection(
            context=context,
            technique="Test Technique",
            description="This is a test detection",
            address=0x401000,
            confidence=0.8,
            evidence="Test evidence",
            test_metadata="test_value"
        )


# Example usage
if __name__ == "__main__":
    from .analysis_context import AnalysisContext
    
    # Test the base detector
    context = AnalysisContext("test.exe")
    monitor = TaskMonitor(lambda msg, prog: print(f"{prog*100:.1f}% - {msg}"))
    
    detector = TestDetector()
    print(f"Detector: {detector}")
    
    detector.analyze(context, monitor)
    
    print(f"Results: {len(context.get_results())}")
    for result in context.get_results():
        print(f"  {result}")
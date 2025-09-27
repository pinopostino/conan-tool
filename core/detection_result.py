"""
CONAN Detection Result - Python Implementation
Translated from Java DetectionResult.java
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional


@dataclass
class DetectionResult:
    """
    Represents a single detection result from CONAN analysis.
    Immutable result object with builder pattern support.
    """
    detector_name: str
    technique_name: str
    description: str
    address: int
    confidence: float
    evidence: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        # Clamp confidence between 0.0 and 1.0
        self.confidence = max(0.0, min(1.0, self.confidence))
        
        # Ensure metadata is a copy
        if self.metadata is None:
            self.metadata = {}
        else:
            self.metadata = dict(self.metadata)
    
    def __str__(self) -> str:
        """String representation matching Java toString()"""
        return f"[{self.detector_name}] {self.technique_name} @ 0x{self.address:x} ({self.confidence*100:.0f}% confidence): {self.description}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'detector_name': self.detector_name,
            'technique_name': self.technique_name,
            'description': self.description,
            'address': f"0x{self.address:x}",
            'address_int': self.address,
            'confidence': self.confidence,
            'confidence_percent': f"{self.confidence*100:.1f}%",
            'evidence': self.evidence,
            'metadata': self.metadata.copy()
        }


class DetectionResultBuilder:
    """
    Builder pattern for DetectionResult - matches Java Builder class
    """
    
    def __init__(self):
        self._detector_name: Optional[str] = None
        self._technique_name: Optional[str] = None
        self._description: Optional[str] = None
        self._address: int = 0
        self._confidence: float = 0.0
        self._evidence: Optional[str] = None
        self._metadata: Dict[str, Any] = {}
    
    def detector(self, name: str) -> 'DetectionResultBuilder':
        """Set detector name"""
        self._detector_name = name
        return self
    
    def technique(self, name: str) -> 'DetectionResultBuilder':
        """Set technique name"""
        self._technique_name = name
        return self
    
    def description(self, desc: str) -> 'DetectionResultBuilder':
        """Set description"""
        self._description = desc
        return self
    
    def address(self, addr: int) -> 'DetectionResultBuilder':
        """Set address"""
        self._address = addr
        return self
    
    def confidence(self, conf: float) -> 'DetectionResultBuilder':
        """Set confidence (clamped between 0.0 and 1.0)"""
        self._confidence = max(0.0, min(1.0, conf))
        return self
    
    
    def evidence(self, ev: str) -> 'DetectionResultBuilder':
        """Set evidence"""
        self._evidence = ev
        return self
    
    def metadata(self, key: str, value: Any) -> 'DetectionResultBuilder':
        """Add metadata key-value pair"""
        self._metadata[key] = value
        return self
    
    def build(self) -> DetectionResult:
        """Build the DetectionResult"""
        if not self._detector_name:
            raise ValueError("Detector name is required")
        if not self._technique_name:
            raise ValueError("Technique name is required")
        if not self._description:
            raise ValueError("Description is required")
        
        return DetectionResult(
            detector_name=self._detector_name,
            technique_name=self._technique_name,
            description=self._description,
            address=self._address,
            confidence=self._confidence,
            evidence=self._evidence,
            metadata=self._metadata.copy()
        )


# Convenience function to create builder
def create_result() -> DetectionResultBuilder:
    """Create a new DetectionResult builder"""
    return DetectionResultBuilder()


# Example usage:
if __name__ == "__main__":
    # Test the DetectionResult implementation
    result = (create_result()
              .detector("AntiDebugDetector")
              .technique("API Call")
              .description("Call to IsDebuggerPresent")
              .address(0x401000)
              .confidence(0.9)
              .evidence("IsDebuggerPresent API")
              .metadata("api_name", "IsDebuggerPresent")
              .build())
    
    print(result)
    print(f"JSON: {result.to_dict()}")
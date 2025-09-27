"""

Questa è la classe centrale del tool CONAN che gestisce tutto il contesto
di analisi di un file. Funziona come un "contenitore intelligente" che:

- Mantiene i dati del binario (sezioni, import, export, bytes raw)
- Gestisce una cache per ottimizzare le operazioni ripetute
- Raccoglie tutti i risultati delle detection dei vari detector
- È fondamentalmente il "cervello" che coordina tutto il processo di analisi

"""


from typing import Dict, Any, List, Optional, TypeVar, Type
from .detection_result import DetectionResult

T = TypeVar('T')


class AnalysisContext:


    """
      Inizializza il contesto di analisi per un binario specifico
      Prepara tutte le strutture dati vuote che verranno popolate durante l'analisi:
      - Cache per memorizzare calcoli costosi
      - Lista dei risultati delle detection
      - Metadati del binario (architettura, entry point, ecc.)
      Il binary_path è l'unico parametro obbligatorio - tutto il resto viene scoperto dinamicamente

    """
    
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self._cache: Dict[str, Any] = {}
        self._results: List[DetectionResult] = []
        
        # Will be set by binary parser
        self.binary_data: Optional[Any] = None  # PE/ELF object
        self.file_data: Optional[bytes] = None  # Raw file bytes
        self.architecture: Optional[str] = None
        self.entry_point: Optional[int] = None
        self.sections: List[Dict[str, Any]] = []
        self.imports: List[Dict[str, Any]] = []
        self.exports: List[Dict[str, Any]] = []
    
    def get_binary_path(self) -> str:
        """Get the binary file path"""
        return self.binary_path
    
    """
    Sistema di caching per evitare ricalcoli 
      Ad esempio, se un detector calcola l'entropia di una sezione,
      la salva qui così altri detector non devono ricalcolarla
    
    """
    def cache_value(self, key: str, value: Any) -> None:
        """Cache a value for later retrieval"""
        self._cache[key] = value


    """
     Recupera un valore dalla cache con controllo di tipo opzionale
         Il parametro value_type è utile per sicurezza: se chiedi un int
         ma nella cache c'è una stringa, ritorna None invece di crashare
         Previene errori runtime difficili da debuggare

    """
    

    def get_cached_value(self, key: str, value_type: Type[T] = None) -> Optional[T]:
        """Get cached value with optional type check"""
        value = self._cache.get(key)
        if value is not None and value_type is not None:
            if isinstance(value, value_type):
                return value
            else:
                return None
        return value
    



    def has_cached_value(self, key: str) -> bool:
        """Check if a value is cached"""
        return key in self._cache
    
    """
    # Aggiunge un risultato di detection alla collezione
        -gni detector chiama questa funzione quando trova qualcosa di sospetto
        -Il  /* 540
        .-no accumulati qui per generare il report finale
        # È il punto centrale dove convergono tutte le scoperte dell'analisi

    """
    
    def add_result(self, result: DetectionResult) -> None:
        """Add a detection result"""
        self._results.append(result)
    
    def get_results(self) -> List[DetectionResult]:
        """Get all detection results (returns copy)"""
        return self._results.copy()
    
    def get_result_count(self) -> int:
        """Get number of results"""
        return len(self._results)
    
    def get_results_by_detector(self, detector_name: str) -> List[DetectionResult]:
        """Get results filtered by detector name"""
        return [r for r in self._results if r.detector_name == detector_name]
    
    def get_results_by_technique(self, technique_name: str) -> List[DetectionResult]:
        """Get results filtered by technique name"""
        return [r for r in self._results if r.technique_name == technique_name]
    
    def get_high_confidence_results(self, threshold: float = 0.8) -> List[DetectionResult]:
        """Get results with confidence above threshold"""
        return [r for r in self._results if r.confidence >= threshold]
    
    def clear_results(self) -> None:
        """Clear all results"""
        self._results.clear()
    
    def clear_cache(self) -> None:
        """Clear the cache"""
        self._cache.clear()
    
    # Binary analysis helper methods (will be implemented with LIEF/pefile)
    
    def get_section_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Get section by name"""
        for section in self.sections:
            if section.get('name', '').lower() == name.lower():
                return section
        return None
    
    def get_section_by_address(self, address: int) -> Optional[Dict[str, Any]]:
        """Get section containing the given address"""
        for section in self.sections:
            start = section.get('virtual_address', 0)
            size = section.get('virtual_size', 0)
            if start <= address < start + size:
                return section
        return None
    
    def get_executable_sections(self) -> List[Dict[str, Any]]:
        """Get all executable sections"""
        return [s for s in self.sections if s.get('executable', False)]
    
    def get_import_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Get import by function name"""
        for imp in self.imports:
            if imp.get('name', '').lower() == name.lower():
                return imp
        return None
    
    def has_import(self, name: str) -> bool:
        """Check if binary imports a specific function"""
        return self.get_import_by_name(name) is not None
    
    def get_file_bytes(self, offset: int = 0, size: Optional[int] = None) -> Optional[bytes]:
        """Get raw file bytes at offset"""
        if self.file_data is None:
            return None
        
        if size is None:
            return self.file_data[offset:]
        else:
            return self.file_data[offset:offset + size]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary for serialization"""
        return {
            'binary_path': self.binary_path,
            'architecture': self.architecture,
            'entry_point': f"0x{self.entry_point:x}" if self.entry_point else None,
            'sections_count': len(self.sections),
            'imports_count': len(self.imports),
            'exports_count': len(self.exports),
            'results_count': len(self._results),
            'cache_keys': list(self._cache.keys())
        }
    
    def __str__(self) -> str:
        return f"AnalysisContext({self.binary_path}, {len(self._results)} results)"


# Example usage and testing
if __name__ == "__main__":
    from .detection_result import create_result
    
    # Test the AnalysisContext
    context = AnalysisContext("test.exe")
    
    # Add some test results
    result1 = (create_result()
               .detector("TestDetector")
               .technique("Test Technique")
               .description("Test detection")
               .address(0x401000)
               .confidence(0.9)
               .build())
    
    context.add_result(result1)
    
    # Test caching
    context.cache_value("test_key", "test_value")
    
    print(context)
    print(f"Results: {len(context.get_results())}")
    print(f"Cached: {context.has_cached_value('test_key')}")
    print(f"Context dict: {context.to_dict()}")
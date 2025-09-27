"""
CONAN Packer Detector - Comprehensive Implementation
Detects executable packing, compression, and obfuscation techniques
"""

import math
import re
import struct
from typing import List, Set, Dict, Any, Tuple, Optional
from core.base_detector import BaseDetector, TaskMonitor
from core.analysis_context import AnalysisContext


class PackerDetector(BaseDetector):
    """
    Detects various executable packing and compression techniques.
    
    Detection categories:
    - Entropy analysis of sections
    - Suspicious section names and characteristics  
    - Import table minimization
    - Entry point analysis
    - Overlay detection
    - Known packer signatures
    - Memory permission anomalies
    - Resource analysis
    """
    
    # Known packer signatures (PE overlay or section patterns)
    PACKER_SIGNATURES = {
        # UPX
        "UPX": [
            b"UPX!",
            b"\x55\x50\x58\x21",  # UPX! signature
            b"$Info: This file is packed with the UPX",
            b"UPX compressed"
        ],
        
        # PECompact
        "PECompact": [
            b"PECompact2",
            b"PEC2",
            b"\x50\x45\x43\x32",  # PEC2
            b"pec.exe"
        ],
        
        # ASPack
        "ASPack": [
            b"ASPack",
            b"aPlib",
            b"ASProtect",
            b"\x00ASPack"
        ],
        
        # Themida/WinLicense
        "Themida": [
            b"Themida",
            b"WinLicense", 
            b"Oreans",
            b"SecuROM"
        ],
        
        # VMProtect
        "VMProtect": [
            b"VMProtect",
            b".vmp0",
            b".vmp1",
            b"VMP"
        ],
        
        # Armadillo
        "Armadillo": [
            b"Armadillo",
            b"Software Passport",
            b"\x41\x72\x6D\x61\x64\x69\x6C\x6C\x6F"
        ],
        
        # FSG
        "FSG": [
            b"FSG",
            b"f.s.g.",
            b"FastSecureGenerator"
        ],
        
        # MEW (Matt's Executable Wrapper)
        "MEW": [
            b"MEW",
            b"\x4D\x45\x57",
            b"\xE9\x00\x00\x00\x00\x5D\x81\xED"  # MEW entry point pattern
        ],
        
        # Petite
        "Petite": [
            b"Petite",
            b"petite.exe",
            b"\x50\x65\x74\x69\x74\x65"
        ],
        
        # MPRESS
        "MPRESS": [
            b"MPRESS",
            b"mpress.exe",
            b"\x4D\x50\x52\x45\x53\x53"
        ],
        
        # Molebox
        "Molebox": [
            b"MoleBox",
            b"molebox",
            b"MoleStudio"
        ],
        
        # ExePressor
        "ExePressor": [
            b"ExePressor",
            b"exepressor",
            b"\x45\x78\x65\x50\x72\x65\x73\x73\x6F\x72"
        ],
        
        # NsPack
        "NsPack": [
            b"NsPack",
            b"nspack",
            b"\x4E\x73\x50\x61\x63\x6B"
        ],
        
        # RLPack
        "RLPack": [
            b"RLPack",
            b"rlpack",
            b"RunLengthPack"
        ]
    }
    
    # Suspicious section names that indicate packing
    SUSPICIOUS_SECTION_NAMES = {
        # UPX sections
        ".upx0", ".upx1", ".upx2",
        
        # Generic packer sections (REDUCED - removed too generic ones)
        ".packed", ".compress", ".data!", ".enigma", ".perplex",
        ".themida", ".winlice", ".vmp0", ".vmp1",
        ".aspack", ".adata", ".tdata", ".rdata!", ".bss!",
        
        # Obfuscated names
        ".", "..", "...", "....", "     ", "\x00\x00\x00\x00",
        "CODE", "DATA", "BSS", "INIT",
        
        # Anti-analysis sections (REDUCED - removed generic .protect)
        ".enigma1", ".enigma2", ".themida1", ".themida2", ".vmprotect",
        
        # Single character sections (often obfuscation)
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
        "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"
    }
    
    # Minimal import patterns that suggest packing
    MINIMAL_IMPORT_APIS = {
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress", 
        "VirtualAlloc", "VirtualProtect", "VirtualFree",
        "CreateThread", "ResumeThread", "ExitProcess"
    }
    
    # High entropy threshold for packed sections
    ENTROPY_THRESHOLD_HIGH = 7.5  # Very high entropy suggests encryption/compression
    ENTROPY_THRESHOLD_MEDIUM = 6.5  # Medium-high entropy
    
    # Size thresholds
    OVERLAY_SIZE_THRESHOLD = 1024  # Minimum overlay size to consider suspicious
    SECTION_SIZE_RATIO = 0.8  # If one section > 80% of file, suspicious
    
    def __init__(self):
        super().__init__("PackerDetector", "Detects executable packing and compression")
    
    def analyze(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """
        Main analysis method - coordinates all packer detection techniques
        """
        monitor.set_message("Analyzing packing techniques...")
        
        # Signature-based detection
        self._detect_packer_signatures(context, monitor)
        if monitor.is_cancelled(): return
        
        # Section analysis
        self._analyze_section_characteristics(context, monitor)
        if monitor.is_cancelled(): return
        
        self._analyze_section_entropy(context, monitor)
        if monitor.is_cancelled(): return
        
        # Import table analysis
        self._analyze_import_minimization(context, monitor)
        if monitor.is_cancelled(): return
        
        # Entry point analysis
        self._analyze_entry_point(context, monitor) 
        if monitor.is_cancelled(): return
        
        # Overlay detection
        self._detect_overlay_data(context, monitor)
        if monitor.is_cancelled(): return
        
        # Resource analysis
        self._analyze_resources(context, monitor)
        if monitor.is_cancelled(): return
        
        # Advanced heuristics
        self._analyze_size_anomalies(context, monitor)
        if monitor.is_cancelled(): return
        
        self._detect_virtualization_artifacts(context, monitor)
    
    def _detect_packer_signatures(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect known packer signatures"""
        monitor.set_message("Scanning for packer signatures...")
        
        if context.file_data is None:
            return
        
        for packer_name, signatures in self.PACKER_SIGNATURES.items():
            if monitor.is_cancelled(): return
            
            for signature in signatures:
                offset = 0
                while True:
                    index = context.file_data.find(signature, offset)
                    if index == -1:
                        break
                    
                    # Calculate confidence based on packer type
                    packer_confidence = {
                        "UPX": 0.98, "PECompact": 0.95, "Themida": 0.92, "VMProtect": 0.90,
                        "ASPack": 0.90, "Armadillo": 0.88, "FSG": 0.85, "MEW": 0.85,
                        "MPRESS": 0.85, "Petite": 0.85, "Molebox": 0.80
                    }.get(packer_name, 0.85)

                    self.log_detection(
                        context=context,
                        technique="Packer Artifact",  # Changed from "Packer Signature"
                        description=f"{packer_name} packer signature detected",
                        address=index,
                        confidence=packer_confidence,
                        evidence=f"Found {packer_name} signature: {signature[:16].hex()}...",
                        packer_name=packer_name,
                        signature_hex=signature.hex(),
                        signature_type="known_packer"
                    )
                    
                    offset = index + len(signature)
                    
                    # Limit detections per signature to prevent spam
                    break
    
    def _analyze_section_characteristics(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Analyze section names and characteristics for packing indicators"""
        monitor.set_message("Analyzing section characteristics...")
        
        if not context.sections:
            return
        
        # Whitelist COMPLETA di sezioni che possono legittimamente avere RWX
        LEGITIMATE_RWX_SECTIONS = {
            '.text', '.data', '.rdata', '.bss', '.idata', '.edata',
            '.pdata', '.xdata', '.tls', '.rsrc', '.reloc',
            '.eh_frame', '.gcc_except_table',
            '.plt', '.got', '.got.plt',
            '.init', '.fini', '.ctors', '.dtors'
        }
        
        rwx_suspicious_count = 0
        
        for section in context.sections:
            if monitor.is_cancelled(): return
            
            section_name = section.get('name', '').lower().strip()
            virtual_size = section.get('virtual_size', 0)
            raw_size = section.get('raw_size', 0)
            characteristics = section.get('characteristics', 0)
            
            # Check RWX con logica più intelligente
            if characteristics & 0xE0000000:  # RWX
                
                # Calcola un punteggio di sospetto invece di flaggare tutto
                suspicion_score = 0
                reasons = []
                
                # Nome sezione
                if section_name.startswith('/') and section_name[1:].isdigit():
                    suspicion_score += 40
                    reasons.append("numeric name")
                elif section_name in self.SUSPICIOUS_SECTION_NAMES:
                    suspicion_score += 35
                    reasons.append("known packer section")
                elif section_name not in LEGITIMATE_RWX_SECTIONS:
                    suspicion_score += 25
                    reasons.append("non-standard name")
                
                # Dimensione
                if virtual_size < 0x100:
                    suspicion_score += 15
                    reasons.append("very small")
                elif virtual_size > 0x100000:  # > 1MB
                    suspicion_score += 10
                    reasons.append("very large")
                
                # Entropia (se disponibile)
                if hasattr(section, 'entropy') and section.entropy > 7.0:
                    suspicion_score += 30
                    reasons.append("high entropy")
                
                # Solo logga se VERAMENTE sospetto (score >= 50)
                if suspicion_score >= 50:
                    rwx_suspicious_count += 1
                    confidence = min(0.3 + (suspicion_score / 100) * 0.5, 0.85)
                    
                    self.log_detection(
                        context=context,
                        technique="Suspicious RWX Section",
                        description=f"RWX section '{section_name}' - {', '.join(reasons)}",
                        address=section.get('virtual_address', 0),
                        confidence=confidence,
                        evidence=f"Suspicion score: {suspicion_score}/100",
                        section_name=section_name,
                        suspicion_reasons=reasons,
                        suspicion_score=suspicion_score
                    )
        
        # Solo se ci sono MOLTE sezioni sospette
        if rwx_suspicious_count >= 3:  # Aumentato da 5 a 3, ma ora conta solo quelle veramente sospette
            self.log_detection(
                context=context,
                technique="Multiple Suspicious RWX Sections",
                description=f"{rwx_suspicious_count} suspicious RWX sections found",
                address=0,
                confidence=0.70 + min(rwx_suspicious_count * 0.05, 0.25),
                evidence=f"High number of genuinely suspicious RWX sections"
            )
    
    def _analyze_section_entropy(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Calculate and analyze entropy of sections"""
        monitor.set_message("Calculating section entropy...")
        
        if not context.sections or context.file_data is None:
            return
        
        high_entropy_count = 0
        
        for section in context.sections:
            if monitor.is_cancelled(): return
            
            section_name = section.get('name', '')
            raw_address = section.get('raw_address', 0)
            raw_size = section.get('raw_size', 0)
            
            if raw_size == 0 or raw_address + raw_size > len(context.file_data):
                continue
            
            # Extract section data
            section_data = context.file_data[raw_address:raw_address + raw_size]
            
            # Calculate entropy
            entropy = self._calculate_entropy(section_data)
            
            # Determine confidence based on entropy - Enhanced calculation
            if entropy >= self.ENTROPY_THRESHOLD_HIGH:
                confidence = min(0.5 + (entropy - 7.5) * 0.3, 0.95)
                description = f"Very high entropy ({entropy:.2f}) in section {section_name}"
                high_entropy_count += 1
            elif entropy >= self.ENTROPY_THRESHOLD_MEDIUM:
                confidence = min(0.4 + (entropy - 6.5) * 0.25, 0.85)
                description = f"High entropy ({entropy:.2f}) in section {section_name}"
                high_entropy_count += 1
            else:
                continue  # Skip low entropy sections
            
            self.log_detection(
                context=context,
                technique="High Entropy Section",
                description=description,
                address=section.get('virtual_address', 0),
                confidence=confidence,
                evidence=f"Section '{section_name}' entropy: {entropy:.2f}/8.0",
                section_name=section_name,
                entropy_value=entropy,
                entropy_threshold=self.ENTROPY_THRESHOLD_HIGH,
                section_size=raw_size
            )
        
        # Multiple high-entropy sections increase suspicion
        if high_entropy_count >= 2:
            multiple_confidence = min(0.65 + (high_entropy_count * 0.08), 0.95)

            self.log_detection(
                context=context,
                technique="Multiple High-Entropy Sections",
                description=f"Multiple sections with high entropy ({high_entropy_count} sections)",
                address=0,
                confidence=multiple_confidence,
                evidence=f"{high_entropy_count} sections exceed entropy threshold",
                high_entropy_count=high_entropy_count,
                detection_type="multiple_high_entropy"
            )
        
        # Check for excessive RWX sections (indicates packing/obfuscation)
        if hasattr(context, '_rwx_section_count'):
            rwx_count = context._rwx_section_count
            total_sections = len(context.sections)
            
            if rwx_count >= 5:  # Many RWX sections
                confidence = min(0.70 + (rwx_count - 5) * 0.05, 0.95)
                self.log_detection(
                    context=context,
                    technique="Excessive RWX Sections",
                    description=f"Suspicious number of RWX sections ({rwx_count}/{total_sections})",
                    address=0,
                    confidence=confidence,
                    evidence=f"{rwx_count} out of {total_sections} sections have RWX permissions",
                    rwx_section_count=rwx_count,
                    total_sections=total_sections,
                    detection_type="excessive_rwx_sections"
                )
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _analyze_import_minimization(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect minimal import tables typical of packers"""
        monitor.set_message("Analyzing import minimization...")
        
        if not context.imports:
            # No imports at all - very suspicious
            self.log_detection(
                context=context,
                technique="No Imports",
                description="Binary has no import table",
                address=0,
                confidence=0.95,
                evidence="Complete absence of import table suggests packing",
                import_count=0,
                detection_type="no_imports"
            )
            return
        
        total_imports = len(context.imports)
        minimal_apis_found = []
        
        # Check for minimal loader APIs
        for import_entry in context.imports:
            api_name = import_entry.get('name', '')
            if api_name in self.MINIMAL_IMPORT_APIS:
                minimal_apis_found.append(api_name)
        
        # Analyze import characteristics
        if total_imports <= 10:
            minimal_confidence = max(0.60, 0.95 - (total_imports * 0.05))

            self.log_detection(
                context=context,
                technique="Minimal Import Table",
                description=f"Very small import table ({total_imports} imports)",
                address=0,
                confidence=minimal_confidence,
                evidence=f"Only {total_imports} imported functions - typical of packed executables",
                import_count=total_imports,
                detection_type="minimal_imports"
            )
        
        # Check for dynamic loading pattern
        if len(minimal_apis_found) >= 3:
            loader_confidence = min(0.70 + (len(minimal_apis_found) * 0.05), 0.90)

            self.log_detection(
                context=context,
                technique="Dynamic Loading Pattern",
                description="Imports suggest dynamic API loading",
                address=0,
                confidence=loader_confidence,
                evidence=f"Found loader APIs: {', '.join(minimal_apis_found)}",
                loader_apis=minimal_apis_found,
                detection_type="dynamic_loading"
            )
        
        # Check import/export ratio
        export_count = len(context.exports) if context.exports else 0
        if export_count == 0 and total_imports < 20:
            export_confidence = max(0.75, 0.95 - (total_imports * 0.02))

            self.log_detection(
                context=context,
                technique="No Exports with Minimal Imports",
                description="No exports and very few imports",
                address=0,
                confidence=export_confidence,
                evidence=f"{total_imports} imports, 0 exports - common packer pattern",
                import_count=total_imports,
                export_count=export_count
            )
    
    def _analyze_entry_point(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Analyze entry point for packing indicators"""
        monitor.set_message("Analyzing entry point...")
        
        entry_point = context.entry_point
        if entry_point == 0 or not context.sections:
            return
        
        # Find which section contains the entry point
        entry_section = None
        for section in context.sections:
            va_start = section.get('virtual_address', 0)
            va_size = section.get('virtual_size', 0)
            
            if va_start <= entry_point < va_start + va_size:
                entry_section = section
                break
        
        if entry_section:
            section_name = entry_section.get('name', '').lower()
            
            # Entry point in suspicious section
            if section_name in [s.lower() for s in self.SUSPICIOUS_SECTION_NAMES]:
                self.log_detection(
                    context=context,
                    technique="Entry Point in Suspicious Section",
                    description=f"Entry point in suspicious section: {section_name}",
                    address=entry_point,
                    confidence=0.88,
                    evidence=f"Entry point (0x{entry_point:x}) in section '{section_name}'",
                    section_name=section_name,
                    entry_point=entry_point
                )
            
            # Entry point not in .text section
            if section_name not in ['.text', 'code', '_text']:
                self.log_detection(
                    context=context,
                    technique="Entry Point Outside Text Section",
                    description=f"Entry point in non-standard section: {section_name}",
                    address=entry_point,
                    confidence=0.75,
                    evidence=f"Entry point in '{section_name}' instead of typical .text section",
                    section_name=section_name,
                    entry_point=entry_point
                )
    
    def _detect_overlay_data(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect overlay data appended to the PE"""
        monitor.set_message("Detecting overlay data...")
        
        if not context.sections or context.file_data is None:
            return
        
        # Calculate the end of the last section
        last_section_end = 0
        for section in context.sections:
            raw_addr = section.get('raw_address', 0)
            raw_size = section.get('raw_size', 0)
            section_end = raw_addr + raw_size
            if section_end > last_section_end:
                last_section_end = section_end
        
        file_size = len(context.file_data)
        overlay_size = file_size - last_section_end
        
        if overlay_size > self.OVERLAY_SIZE_THRESHOLD:
            # Calculate overlay entropy
            overlay_data = context.file_data[last_section_end:]
            overlay_entropy = self._calculate_entropy(overlay_data)
            
            if overlay_entropy > self.ENTROPY_THRESHOLD_MEDIUM:
                overlay_confidence = min(0.60 + (overlay_entropy - 6.5) * 0.15, 0.90)

                self.log_detection(
                    context=context,
                    technique="Overlay Data",
                    description=f"Suspicious overlay data ({overlay_size} bytes)",
                    address=last_section_end,
                    confidence=overlay_confidence,
                    evidence=f"Overlay: {overlay_size} bytes at offset 0x{last_section_end:x}, entropy: {overlay_entropy:.2f}",
                    overlay_size=overlay_size,
                    overlay_offset=last_section_end,
                    overlay_entropy=overlay_entropy
                )
    
    def _analyze_resources(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Analyze PE resources for packing indicators"""
        monitor.set_message("Analyzing resources...")
        
        # This is a placeholder - full resource analysis would require 
        # parsing the PE resource directory
        # For now, check for resource-related strings in the binary
        
        if context.file_data is None:
            return
        
        try:
            file_str = context.file_data.decode('latin1', errors='ignore').lower()
            
            # Resource-related patterns that might indicate packing (REDUCED - removed generic strings)
            resource_patterns = [
                "rcdata", "compress", "packed", "encrypted", 
                "stub", "dropper", "payload"  # Removed "protect" and "loader" - too generic
            ]
            
            for pattern in resource_patterns:
                if monitor.is_cancelled(): return
                
                if pattern in file_str:
                    offset = file_str.find(pattern)
                    
                    resource_confidence = {
                        "rcdata": 0.85, "compress": 0.80, "packed": 0.85,
                        "encrypted": 0.90, "stub": 0.75, "dropper": 0.85, "payload": 0.80
                    }.get(pattern, 0.70)

                    self.log_detection(
                        context=context,
                        technique="Suspicious Resource Pattern",
                        description=f"Suspicious resource-related string: {pattern}",
                        address=offset,
                        confidence=resource_confidence,
                        evidence=f"Found resource pattern: '{pattern}'",
                        pattern=pattern,
                        detection_type="resource_pattern"
                    )
        except Exception:
            pass
    
    def _analyze_size_anomalies(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect size-related anomalies"""
        monitor.set_message("Analyzing size anomalies...")
        
        if not context.sections:
            return
        
        file_size = context.get_cached_value("file_size")
        if not file_size or file_size == 0:
            return
        
        # Check for one dominant section
        for section in context.sections:
            if monitor.is_cancelled(): return
            
            section_name = section.get('name', '')
            virtual_size = section.get('virtual_size', 0)
            
            if virtual_size / file_size > self.SECTION_SIZE_RATIO:
                dominant_confidence = min(0.65 + (virtual_size/file_size - 0.8) * 0.5, 0.90)

                self.log_detection(
                    context=context,
                    technique="Dominant Section",
                    description=f"Section {section_name} dominates the file ({virtual_size/file_size*100:.1f}%)",
                    address=section.get('virtual_address', 0),
                    confidence=dominant_confidence,
                    evidence=f"Section '{section_name}' is {virtual_size/file_size*100:.1f}% of file size",
                    section_name=section_name,
                    section_ratio=virtual_size/file_size,
                    detection_type="dominant_section"
                )
    
    def _detect_virtualization_artifacts(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect virtualization-based protection artifacts"""
        monitor.set_message("Detecting virtualization artifacts...")
        
        if context.file_data is None:
            return
        
        # VM-based protector patterns (REDUCED - removed generic strings)
        vm_patterns = [
            b"vmp", b"vmware", b"themida", b"winlicense", b"obsidium", b"enigma"
            # Removed "vm", "virtual", "protect", "guard" - too generic and cause GCC false positives
        ]
        
        try:
            file_str = context.file_data.decode('latin1', errors='ignore').lower()
            
            vm_detections = 0
            for pattern in vm_patterns:
                if monitor.is_cancelled(): return
                
                pattern_str = pattern.decode('latin1').lower()
                if pattern_str in file_str:
                    offset = file_str.find(pattern_str)
                    vm_detections += 1
                    
                    # Determine correct technique based on pattern
                    if pattern_str in ["themida", "winlicense", "obsidium", "enigma"]:
                        technique = "Packer Artifact"
                        description = f"Code protector artifact: {pattern_str}"
                        confidence = 0.90
                    else:
                        technique = "Virtualization Artifact"
                        description = f"VM protection artifact: {pattern_str}"
                        confidence = 0.75

                    self.log_detection(
                        context=context,
                        technique=technique,
                        description=description,
                        address=offset,
                        confidence=confidence,
                        evidence=f"Found protection-related string: '{pattern_str}'",
                        pattern_string=pattern_str,
                        detection_type="protection_artifact"
                    )
            
            # Multiple VM artifacts increase detection reliability
            if vm_detections >= 3:
                multiple_vm_confidence = min(0.80 + (vm_detections * 0.05), 0.95)

                self.log_detection(
                    context=context,
                    technique="Multiple VM Artifacts",
                    description=f"Multiple virtualization artifacts detected ({vm_detections})",
                    address=0,
                    confidence=multiple_vm_confidence,
                    evidence=f"Found {vm_detections} VM-related patterns",
                    vm_artifact_count=vm_detections,
                    detection_type="multiple_vm_artifacts"
                )
        except Exception:
            pass
    
    def get_supported_techniques(self) -> List[str]:
        """Get list of supported detection techniques"""
        return [
            "Packer Signature",
            "Suspicious Section Name", 
            "Suspicious RWX Section",
            "Size Mismatch",
            "High Suspicious Section Ratio",
            "High Entropy Section",
            "Multiple High-Entropy Sections",
            "Excessive RWX Sections",
            "No Imports",
            "Minimal Import Table",
            "Dynamic Loading Pattern", 
            "No Exports with Minimal Imports",
            "Entry Point in Suspicious Section",
            "Entry Point Outside Text Section",
            "Overlay Data",
            "Suspicious Resource Pattern",
            "Dominant Section",
            "Virtualization Artifact",
            "Multiple VM Artifacts"
        ]
    
    def get_packer_families(self) -> List[str]:
        """Get list of detected packer families"""
        return list(self.PACKER_SIGNATURES.keys())


# Example usage and testing
if __name__ == "__main__":
    from core.analysis_context import AnalysisContext
    from core.base_detector import TaskMonitor
    
    # Test the detector
    detector = PackerDetector()
    print(f"Detector: {detector}")
    print(f"Supported techniques: {detector.get_supported_techniques()}")
    print(f"Known packers: {detector.get_packer_families()}")
    
    # This would be used with actual binary analysis
    # context = AnalysisContext("packed_sample.exe")
    # monitor = TaskMonitor()
    # detector.analyze(context, monitor)
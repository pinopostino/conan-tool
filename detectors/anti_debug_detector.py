"""
CONAN Anti-Debug Detector - Python Implementation
Translated from Java AntiDebugDetector.java
"""

import re
from typing import List, Set, Dict, Any
from core.base_detector import BaseDetector, TaskMonitor
from core.analysis_context import AnalysisContext


class AntiDebugDetector(BaseDetector):
    """
    Detects various anti-debugging techniques in Windows PE files.
    
    Detection categories:
    - API-based anti-debug calls
    - PEB (Process Environment Block) access
    - Timing attacks (RDTSC, GetTickCount, etc.)
    - Hardware breakpoint detection
    - SEH (Structured Exception Handling) manipulation
    - Advanced timing APIs
    """
    
    # Anti-debug API constants - ESPANSE!
    ANTI_DEBUG_APIS = {
        # Basic API detection
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent", 
        "NtQueryInformationProcess",
        "ZwQueryInformationProcess",
        "OutputDebugStringA",
        "OutputDebugStringW",
        
        # Thread/Context manipulation
        "GetThreadContext",
        "SetThreadContext", 
        "NtGetContextThread",
        "NtSetContextThread",
        "SuspendThread",
        "ResumeThread",
        "NtSetInformationThread",  # ThreadHideFromDebugger
        
        # Process information
        "NtQuerySystemInformation",
        "NtQueryObject",
        "RtlQueryProcessHeapInformation",
        "GetProcessHeap",
        "HeapWalk",
        
        # Handle manipulation
        "NtClose",
        "CloseHandle",
        "DuplicateHandle",
        
        # Toolhelp32 debugger detection
        "CreateToolhelp32Snapshot",
        "Process32First",
        "Process32Next",
        "Module32First", 
        "Module32Next",
        
        # Window detection APIs
        "FindWindowA",
        "FindWindowW",
        "FindWindowExA",
        "FindWindowExW",
        "EnumWindows",
        "GetWindowTextA",
        "GetWindowTextW",
        "GetClassName",
        
        # Registry detection (only specific anti-debug registry queries)
        "RegQueryValueExA",
        "RegQueryValueExW",
        
        # File system detection (only specific anti-debug files)
        # GetModuleHandle* removed - too generic  
        # CreateFile* removed - too generic
    }
    
    # SEH manipulation APIs (only specific anti-debug ones)
    SEH_APIS = {
        # "SetUnhandledExceptionFilter" - removed: too common, used legitimately
        "AddVectoredExceptionHandler",  # More suspicious for anti-debug
        "RemoveVectoredExceptionHandler",  # More suspicious for anti-debug
        # "RaiseException" - removed: too generic
    }
    
    # Advanced timing APIs
    TIMING_APIS = {
        "QueryPerformanceCounter",
        "GetLocalTime",
        "GetSystemTime", 
        "timeGetTime",
        "ZwGetTickCount",
        "KiGetTickCount",
        "GetTickCount"
    }
    
    # PEB offset patterns - Enhanced detection
    PEB_PATTERNS = [
        # BeingDebugged flag at PEB+0x02 (fs:[0x30] + 0x02)
        (rb'\x64\x8B\x05\x30\x00\x00\x00', "PEB Access via fs:[0x30]", "Direct access to PEB structure", 0.90),
        (rb'\x64\x8B\x15\x30\x00\x00\x00', "PEB Access via fs:[0x30]", "Direct access to PEB structure", 0.90),
        (rb'\x64\xA1\x30\x00\x00\x00', "PEB Access via fs:[0x30]", "MOV EAX, fs:[0x30] - PEB access", 0.95),

        # BeingDebugged flag checks (PEB+0x02)
        (rb'\x8A\x40\x02', "BeingDebugged Flag", "MOV AL, [EAX+2] - BeingDebugged check", 0.95),
        (rb'\x80\x78\x02\x00', "BeingDebugged Flag", "CMP BYTE PTR [EAX+2], 0 - BeingDebugged test", 0.98),

        # NtGlobalFlag checks (PEB+0x68)
        (rb'\x8B\x40\x68', "NtGlobalFlag Check", "MOV EAX, [EAX+0x68] - NtGlobalFlag access", 0.92),
        (rb'\x8B\x48\x68', "NtGlobalFlag Check", "MOV ECX, [EAX+0x68] - NtGlobalFlag access", 0.92),
        (rb'\xF7\x40\x68', "NtGlobalFlag Check", "TEST [EAX+0x68] - NtGlobalFlag test", 0.94),

        # Heap flags manipulation (ProcessHeap+0x10, +0x14)
        (rb'\x8B\x40\x18\x8B\x40\x10', "Heap Flags Check", "Access to ProcessHeap.Flags", 0.88),
        (rb'\x8B\x40\x18\x8B\x40\x14', "Heap ForceFlags Check", "Access to ProcessHeap.ForceFlags", 0.90),

        # 64-bit PEB patterns
        (rb'\x65\x48\x8B\x04\x25\x60\x00\x00\x00', "PEB64 Access", "64-bit PEB access via gs:[0x60]", 0.90),

        # SEH chain manipulation
        (rb'\x64\x8B\x25\x00\x00\x00\x00', "SEH Chain Access", "Access to fs:[0] - SEH chain", 0.85)
    ]
    
    # Debug register patterns
    DEBUG_REGISTER_PATTERN = re.compile(r'\bdr[0-7]\b', re.IGNORECASE)
    
    # Timing instruction patterns - ESPANSO
    TIMING_INSTRUCTIONS = {"rdtsc", "rdpmc", "cpuid"}
    
    # Debugger process names (case insensitive)
    DEBUGGER_PROCESSES = {
        "ollydbg.exe", "x32dbg.exe", "x64dbg.exe", "windbg.exe", "ida.exe", "ida64.exe",
        "idag.exe", "idag64.exe", "idaw.exe", "idaw64.exe", "idaq.exe", "idaq64.exe",
        "scylla.exe", "scylla_x64.exe", "scylla_x86.exe", "lordpe.exe", "importrec.exe",
        "wireshark.exe", "filemon.exe", "regmon.exe", "procmon.exe", "vmware-vmx.exe",
        "python.exe", "devenv.exe", "msdev.exe", "wt.exe", "fiddler.exe", "hiew32.exe"
    }
    
    # Debugger window class names
    DEBUGGER_WINDOW_CLASSES = {
        "OLLYDBG", "X32DbgClass", "X64DbgClass", "WinDbgFrameClass", "idaWindow", 
        "TIdaWindow", "TApplication", "Qt5QWindowIcon", "Notepad++", "HexWorkshopWindowClass"
    }
    
    # Debugger window titles (partial matches)
    DEBUGGER_WINDOW_TITLES = {
        "olly", "x32dbg", "x64dbg", "windbg", "ida pro", "immunity debugger", 
        "hiew", "lordpe", "peid", "exeinfo", "resource hacker", "hex workshop",
        "process monitor", "api monitor", "regshot", "process hacker"
    }
    
    # Registry keys for debugger detection
    DEBUGGER_REGISTRY_KEYS = {
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug",
        "SOFTWARE\\Classes\\ms-msdt",  # Windows troubleshooting
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Debug Print Filter",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Debug",
        "SOFTWARE\\Policies\\Microsoft\\Windows\\System\\EnableLUA"  # UAC bypass detection
    }
    
    # Interrupt and exception patterns
    INTERRUPT_PATTERNS = [
        (rb'\xCD\x03', "INT3 Breakpoint", "Software breakpoint interrupt", 0.85),
        (rb'\xCD\x2D', "INT 2D", "Kernel debugger detection interrupt", 0.88),
        (rb'\xCD\x01', "INT1 Single Step", "Single step interrupt for tracing detection", 0.82),
        (rb'\xCC', "INT3 Opcode", "0xCC software breakpoint", 0.90),
        (rb'\xF1', "ICEBP", "ICE breakpoint undocumented instruction", 0.92),
        # Multiple consecutive INT3 patterns (suspicious)
        (rb'\xCC\xCC', "Multiple INT3", "Two consecutive INT3 breakpoints", 0.95),
        (rb'\xCC\xCC\xCC', "Multiple INT3", "Three consecutive INT3 breakpoints", 0.98),
        (rb'\xCC\xCC\xCC\xCC', "Multiple INT3", "Four or more consecutive INT3 breakpoints", 0.99)
    ]
    
    def __init__(self):
        super().__init__("AntiDebugDetector", "Detects anti-debugging techniques")
    
    def analyze(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """
        Main analysis method - coordinates all anti-debug detection techniques
        """
        monitor.set_message("Analyzing anti-debug techniques...")
        
        # Basic API detection
        self._detect_anti_debug_apis(context, monitor)
        if monitor.is_cancelled(): return
        
        # PEB/Heap manipulation detection
        self._detect_peb_access(context, monitor) 
        if monitor.is_cancelled(): return
        
        # Timing-based attacks
        self._detect_timing_checks(context, monitor)
        if monitor.is_cancelled(): return
        self._detect_advanced_timing_apis(context, monitor)
        if monitor.is_cancelled(): return
        
        # Hardware debugging detection
        self._detect_hardware_breakpoints(context, monitor)
        if monitor.is_cancelled(): return
        
        # Exception handling manipulation
        self._detect_seh_manipulation(context, monitor)
        if monitor.is_cancelled(): return
        
        # NEW: Advanced detection techniques
        self._detect_debugger_processes(context, monitor)
        if monitor.is_cancelled(): return
        
        self._detect_debugger_windows(context, monitor)
        if monitor.is_cancelled(): return
        
        self._detect_interrupt_patterns(context, monitor)
        if monitor.is_cancelled(): return
        
        self._detect_registry_keys(context, monitor)
        if monitor.is_cancelled(): return
        
        self._detect_advanced_heap_checks(context, monitor)
    
    def _detect_anti_debug_apis(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect anti-debug API calls"""
        monitor.set_message("Checking anti-debug API calls...")

        # Calculate confidence based on API suspicion level
        api_confidence_map = {
            "IsDebuggerPresent": 0.95,
            "CheckRemoteDebuggerPresent": 0.92,
            "NtQueryInformationProcess": 0.85,
            "OutputDebugStringA": 0.75,
            "OutputDebugStringW": 0.75,
            "GetThreadContext": 0.70,
            "SetThreadContext": 0.72,
            "NtSetInformationThread": 0.88,
            "NtQuerySystemInformation": 0.65,
            "CreateToolhelp32Snapshot": 0.60,
            "FindWindowA": 0.55,
            "FindWindowW": 0.55,
            "RegQueryValueExA": 0.50,
            "RegQueryValueExW": 0.50
        }

        for api_name in self.ANTI_DEBUG_APIS:
            if monitor.is_cancelled(): return

            # Check if binary imports this API
            if context.has_import(api_name):
                import_info = context.get_import_by_name(api_name)

                # Get the import address or use 0 if not available
                address = import_info.get('address', 0) if import_info else 0

                # Get confidence for this specific API
                confidence = api_confidence_map.get(api_name, 0.75)

                self.log_detection(
                    context=context,
                    technique="API-Based Anti-Debug",
                    description=f"Import of {api_name} API",
                    address=address,
                    confidence=confidence,
                    evidence=f"Binary imports {api_name}",
                    api_name=api_name,
                    import_type="direct"
                )

        # TODO: When we add disassembly, also check for dynamic API loading
        # via GetProcAddress calls to these APIs
    
    def _detect_peb_access(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect PEB (Process Environment Block) access patterns"""
        monitor.set_message("Analyzing PEB access patterns...")

        if context.file_data is None:
            return

        try:
            file_data = context.file_data

            for pattern, technique, description, confidence in self.PEB_PATTERNS:
                if monitor.is_cancelled(): return

                # Search for binary patterns in file data
                offset = 0
                count = 0

                while True:
                    index = file_data.find(pattern, offset)
                    if index == -1:
                        break

                    count += 1
                    self.log_detection(
                        context=context,
                        technique=technique,
                        description=description,
                        address=index,
                        confidence=confidence,
                        evidence=f"PEB access pattern at offset 0x{index:x}: {pattern.hex()}",
                        pattern_hex=pattern.hex(),
                        pattern_type="binary_instruction"
                    )

                    offset = index + len(pattern)

                    # Limit to prevent spam
                    if count >= 10:
                        break

        except Exception:
            pass
    
    def _detect_timing_checks(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect timing-based anti-debug checks"""
        monitor.set_message("Checking timing attack patterns...")
        
        if context.file_data is None:
            return
        
        try:
            file_str = context.file_data.decode('latin1', errors='ignore').lower()
            
            # Look for RDTSC instructions (simplified - would use proper disassembly)
            rdtsc_pattern = re.compile(rb'\x0f\x31', re.IGNORECASE)  # RDTSC opcode
            rdtsc_matches = []
            
            for match in rdtsc_pattern.finditer(context.file_data):
                rdtsc_matches.append(match.start())
            
            # Detect RDTSC pairs (timing checks)
            for i in range(len(rdtsc_matches) - 1):
                first_addr = rdtsc_matches[i]
                second_addr = rdtsc_matches[i + 1]
                distance = second_addr - first_addr
                
                if distance < 1000:  # RDTSC instructions close together
                    self.log_detection(
                        context=context,
                        technique="Timing Attack",
                        description="RDTSC timing check pattern detected",
                        address=first_addr,
                        confidence=0.85,  # High confidence for RDTSC pairs
                        evidence=f"RDTSC pair at 0x{first_addr:x} and 0x{second_addr:x}",
                        first_rdtsc=f"0x{first_addr:x}",
                        second_rdtsc=f"0x{second_addr:x}",
                        distance=distance
                    )
            
            # Check for timing API references
            for api in {"gettickcount", "timegettime"}:
                if api in file_str:
                    # Find approximate location
                    offset = file_str.find(api)
                    
                    self.log_detection(
                        context=context,
                        technique="Timing Attack",
                        description=f"{api.upper()} timing check",
                        address=offset,
                        confidence=0.70,  # Medium-high confidence for timing API references
                        evidence=f"{api.upper()} API reference found",
                        timing_api=api
                    )
        
        except Exception:
            pass
    
    def _detect_hardware_breakpoints(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect hardware breakpoint detection techniques (improved precision)"""
        monitor.set_message("Checking hardware breakpoint detection...")
        
        if context.file_data is None:
            return
        
        try:
            # IMPROVED: Look for actual x86 debug register access instruction patterns
            # Instead of naive string search, look for specific MOV instructions
            
            file_data = context.file_data
            detections_found = 0
            
            # x86 instruction patterns for debug register access
            debug_patterns = [
                (b'\x0f\x21\xc0', "MOV EAX, DR0"),  # Read from DR0
                (b'\x0f\x21\xc8', "MOV EAX, DR1"),  # Read from DR1  
                (b'\x0f\x21\xd0', "MOV EAX, DR2"),  # Read from DR2
                (b'\x0f\x21\xd8', "MOV EAX, DR3"),  # Read from DR3
                (b'\x0f\x21\xf0', "MOV EAX, DR6"),  # Read from DR6
                (b'\x0f\x21\xf8', "MOV EAX, DR7"),  # Read from DR7
                (b'\x0f\x23\xc0', "MOV DR0, EAX"),  # Write to DR0
                (b'\x0f\x23\xc8', "MOV DR1, EAX"),  # Write to DR1
                (b'\x0f\x23\xd0', "MOV DR2, EAX"),  # Write to DR2
                (b'\x0f\x23\xd8', "MOV DR3, EAX"),  # Write to DR3
                (b'\x0f\x23\xf0', "MOV DR6, EAX"),  # Write to DR6
                (b'\x0f\x23\xf8', "MOV DR7, EAX"),  # Write to DR7
            ]
            
            for pattern, description in debug_patterns:
                if monitor.is_cancelled(): return
                
                offset = 0
                while True:
                    offset = file_data.find(pattern, offset)
                    if offset == -1:
                        break
                    
                    # Found actual debug register instruction!
                    # Calculate confidence based on instruction type
                    confidence = 0.92 if "DR6" in description or "DR7" in description else 0.88

                    self.log_detection(
                        context=context,
                        technique="Hardware Breakpoint Detection",
                        description=f"Debug register instruction: {description}",
                        address=offset,
                        confidence=confidence,
                        evidence=f"Found {description} instruction at offset {offset:x}",
                        instruction=description
                    )
                    
                    detections_found += 1
                    offset += len(pattern)
            
            # If no actual instructions found, don't report anything
            # (removes the false positives from string matching)
        
        except Exception:
            pass
    
    def _detect_seh_manipulation(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect SEH (Structured Exception Handling) manipulation"""
        monitor.set_message("Analyzing SEH manipulation techniques...")
        
        # Check for SEH-related API imports
        for api_name in self.SEH_APIS:
            if monitor.is_cancelled(): return
            
            if context.has_import(api_name):
                import_info = context.get_import_by_name(api_name)
                address = import_info.get('address', 0) if import_info else 0
                
                # SEH APIs have different confidence levels
                seh_confidence = 0.85 if "Vectored" in api_name else 0.80

                self.log_detection(
                    context=context,
                    technique="SEH Manipulation",
                    description=f"SEH-based anti-debug: {api_name}",
                    address=address,
                    confidence=seh_confidence,
                    evidence=f"Import of {api_name} API",
                    api_name=api_name,
                    manipulation_type="api_based"
                )
        
        # TODO: Add detection for manual SEH chain manipulation via FS:[0]
        # This would require disassembly to detect FS segment access patterns
    
    def _detect_advanced_timing_apis(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect advanced timing API usage"""
        monitor.set_message("Checking advanced timing APIs...")
        
        timing_type_map = {
            "QueryPerformanceCounter": "high_precision",
            "GetLocalTime": "system_time",
            "GetSystemTime": "system_time",
            "timeGetTime": "multimedia_timer",
            "ZwGetTickCount": "kernel_timer",
            "KiGetTickCount": "kernel_timer",
            "GetTickCount": "standard_timer"
        }
        
        for api_name in self.TIMING_APIS:
            if monitor.is_cancelled(): return
            
            if context.has_import(api_name):
                import_info = context.get_import_by_name(api_name)
                address = import_info.get('address', 0) if import_info else 0
                timing_type = timing_type_map.get(api_name, "unknown")
                
                self.log_detection(
                    context=context,
                    technique="Advanced Timing Attack",
                    description=f"High-precision timing API: {api_name}",
                    address=address,
                    confidence=0.75,  # High confidence for imported timing APIs
                    evidence=f"Import of {api_name} for timing measurement",
                    api_name=api_name,
                    timing_type=timing_type
                )
    
    def _detect_debugger_processes(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect debugger process names in strings"""
        monitor.set_message("Checking for debugger process references...")
        
        if context.file_data is None:
            return
        
        try:
            # Search for debugger process names in binary strings
            file_str = context.file_data.decode('latin1', errors='ignore').lower()
            
            for process_name in self.DEBUGGER_PROCESSES:
                if monitor.is_cancelled(): return
                
                if process_name.lower() in file_str:
                    offset = file_str.find(process_name.lower())

                    # Calculate confidence based on how specific the debugger name is
                    debugger_confidence = {
                        "ollydbg.exe": 0.95, "x32dbg.exe": 0.95, "x64dbg.exe": 0.95,
                        "windbg.exe": 0.92, "ida.exe": 0.90, "ida64.exe": 0.90,
                        "scylla.exe": 0.88, "lordpe.exe": 0.88, "importrec.exe": 0.88,
                        "python.exe": 0.30, "devenv.exe": 0.35  # Common dev tools
                    }.get(process_name.lower(), 0.75)

                    self.log_detection(
                        context=context,
                        technique="Debugger Process Detection",
                        description=f"Reference to debugger process: {process_name}",
                        address=offset,
                        confidence=debugger_confidence,
                        evidence=f"String reference to {process_name} found",
                        process_name=process_name,
                        detection_type="process_name"
                    )
        except Exception:
            pass
    
    def _detect_debugger_windows(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect debugger window class/title references"""
        monitor.set_message("Checking for debugger window references...")
        
        if context.file_data is None:
            return
            
        try:
            file_str = context.file_data.decode('latin1', errors='ignore').lower()
            
            # Check window class names
            for class_name in self.DEBUGGER_WINDOW_CLASSES:
                if monitor.is_cancelled(): return
                
                if class_name.lower() in file_str:
                    offset = file_str.find(class_name.lower())
                    
                    # Window class confidence based on specificity
                    window_confidence = 0.90 if "dbg" in class_name.lower() else 0.75

                    self.log_detection(
                        context=context,
                        technique="Debugger Window Detection",
                        description=f"Reference to debugger window class: {class_name}",
                        address=offset,
                        confidence=window_confidence,
                        evidence=f"Window class name {class_name} detected",
                        window_class=class_name,
                        detection_type="window_class"
                    )
            
            # Check window titles
            for title in self.DEBUGGER_WINDOW_TITLES:
                if monitor.is_cancelled(): return
                
                if title in file_str:
                    offset = file_str.find(title)
                    
                    # Title confidence based on specificity
                    title_confidence = 0.85 if any(x in title for x in ["dbg", "debug", "ida"]) else 0.70

                    self.log_detection(
                        context=context,
                        technique="Debugger Window Detection",
                        description=f"Reference to debugger window title: {title}",
                        address=offset,
                        confidence=title_confidence,
                        evidence=f"Window title '{title}' detected",
                        window_title=title,
                        detection_type="window_title"
                    )
        except Exception:
            pass
    
    def _detect_interrupt_patterns(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect interrupt and exception patterns"""
        monitor.set_message("Analyzing interrupt patterns...")
        
        if context.file_data is None:
            return
            
        for pattern, technique, description, confidence in self.INTERRUPT_PATTERNS:
            if monitor.is_cancelled(): return
            
            # Find all occurrences of this interrupt pattern
            offset = 0
            count = 0
            
            while True:
                index = context.file_data.find(pattern, offset)
                if index == -1:
                    break
                    
                count += 1
                self.log_detection(
                    context=context,
                    technique=technique,
                    description=description,
                    address=index,
                    confidence=confidence,
                    evidence=f"Interrupt pattern {pattern.hex()} at offset 0x{index:x}",
                    interrupt_opcode=pattern.hex(),
                    occurrence_count=count
                )
                
                offset = index + len(pattern)
                
                # Limit to prevent spam
                if count >= 20:
                    break
    
    def _detect_registry_keys(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect debugger-related registry key references"""
        monitor.set_message("Checking registry key references...")
        
        if context.file_data is None:
            return
            
        try:
            file_str = context.file_data.decode('latin1', errors='ignore')
            
            for reg_key in self.DEBUGGER_REGISTRY_KEYS:
                if monitor.is_cancelled(): return
                
                # Check both forward and backward slashes
                for key_variant in [reg_key, reg_key.replace('\\', '/')]:
                    if key_variant.lower() in file_str.lower():
                        offset = file_str.lower().find(key_variant.lower())
                        
                        # Registry key confidence based on specificity
                        reg_confidence = {
                            "AeDebug": 0.92,
                            "Image File Execution Options": 0.88,
                            "Debug Print Filter": 0.85
                        }

                        # Find best matching confidence
                        key_confidence = 0.75  # default
                        for key_part, conf in reg_confidence.items():
                            if key_part in reg_key:
                                key_confidence = conf
                                break

                        self.log_detection(
                            context=context,
                            technique="Registry Anti-Debug",
                            description=f"Reference to debug-related registry key",
                            address=offset,
                            confidence=key_confidence,
                            evidence=f"Registry key reference: {reg_key}",
                            registry_key=reg_key,
                            detection_type="registry_reference"
                        )
                        break  # Avoid duplicate detections
        except Exception:
            pass
    
    def _detect_advanced_heap_checks(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect advanced heap manipulation checks"""
        monitor.set_message("Analyzing advanced heap checks...")
        
        # Check for heap-related API imports that might indicate heap flag manipulation
        heap_apis = {
            "HeapCreate", "HeapDestroy", "HeapAlloc", "HeapFree", "HeapReAlloc",
            "HeapSize", "HeapValidate", "HeapCompact", "HeapLock", "HeapUnlock",
            "HeapWalk", "HeapSetInformation", "HeapQueryInformation", "GetProcessHeap",
            "GetProcessHeaps", "RtlCreateHeap", "RtlDestroyHeap", "RtlAllocateHeap"
        }
        
        detected_heap_apis = []
        
        for api_name in heap_apis:
            if monitor.is_cancelled(): return
            
            if context.has_import(api_name):
                detected_heap_apis.append(api_name)
                import_info = context.get_import_by_name(api_name)
                address = import_info.get('address', 0) if import_info else 0
                
                self.log_detection(
                    context=context,
                    technique="Advanced Heap Anti-Debug",
                    description=f"Heap manipulation API: {api_name}",
                    address=address,
                    evidence=f"Import of {api_name} - potential heap flag manipulation",
                    api_name=api_name,
                    heap_operation="heap_api_import"
                )
        
        # If multiple heap APIs are imported, increase suspicion
        if len(detected_heap_apis) >= 3:
            self.log_detection(
                context=context,
                technique="Advanced Heap Anti-Debug",
                description=f"Multiple heap APIs imported ({len(detected_heap_apis)} APIs)",
                address=0,
                evidence=f"Extensive heap API usage: {', '.join(detected_heap_apis[:5])}...",
                heap_api_count=len(detected_heap_apis),
                heap_operation="multiple_apis"
            )
    
    def get_supported_techniques(self) -> List[str]:
        """Get list of supported detection techniques"""
        return [
            # Basic techniques
            "API-Based Anti-Debug",
            "PEB Access",
            "BeingDebugged Flag",
            "NtGlobalFlag Check", 
            "ProcessHeap Access",
            "Heap Flags Check",
            "Heap ForceFlags Check",
            "Heap Signature",
            
            # Timing attacks
            "Timing Attack",
            "Advanced Timing Attack",
            
            # Hardware detection
            "Hardware Breakpoint Detection",
            
            # Exception handling
            "SEH Manipulation",
            "SEH Chain Access",
            
            # Interrupt patterns
            "INT3 Breakpoint",
            "INT 2D",
            "INT1 Single Step",
            "ICEBP",
            
            # Advanced detection
            "Debugger Process Detection",
            "Debugger Window Detection",
            "Registry Anti-Debug",
            "Advanced Heap Anti-Debug",
            
            # PEB advanced fields
            "ProcessParameters",
            "ImageBaseAddress",
            "CrossProcessFlags",
            "TracingFlags"
        ]
    
    def get_api_categories(self) -> Dict[str, List[str]]:
        """Get categorized list of detected APIs"""
        return {
            "anti_debug": list(self.ANTI_DEBUG_APIS),
            "seh_manipulation": list(self.SEH_APIS),
            "timing": list(self.TIMING_APIS)
        }


# Example usage and testing
if __name__ == "__main__":
    from core.analysis_context import AnalysisContext
    from core.base_detector import TaskMonitor
    
    # Test the detector
    detector = AntiDebugDetector()
    print(f"Detector: {detector}")
    print(f"Supported techniques: {detector.get_supported_techniques()}")
    print(f"API categories: {detector.get_api_categories()}")
    
    # This would be used with actual binary analysis
    # context = AnalysisContext("test.exe")
    # monitor = TaskMonitor()
    # detector.analyze(context, monitor)
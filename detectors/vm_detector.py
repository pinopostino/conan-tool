"""
CONAN VM Detector - Virtual Machine Evasion Detection
Detects attempts to evade analysis by detecting virtual machine environments
"""

import re
from typing import List, Set, Dict, Any, Tuple
from core.base_detector import BaseDetector, TaskMonitor
from core.analysis_context import AnalysisContext


class VMDetector(BaseDetector):
    """
    Detects various virtual machine evasion techniques.
    
    Detection categories:
    - VMware detection techniques
    - VirtualBox detection techniques  
    - Hyper-V detection techniques
    - QEMU detection techniques
    - Generic VM detection methods
    - Hardware fingerprinting
    - Registry key detection
    - File system artifacts
    - Process detection
    - Service detection
    """
    
    # VMware detection artifacts
    VMWARE_ARTIFACTS = {
        # Registry keys
        "registry_keys": [
            "SOFTWARE\\VMware, Inc.\\VMware Tools",
            "SOFTWARE\\VMware",
            "HARDWARE\\ACPI\\DSDT\\VBOX__",
            "HARDWARE\\ACPI\\FADT\\VBOX__", 
            "HARDWARE\\ACPI\\RSDT\\VBOX__",
            "SYSTEM\\ControlSet001\\Services\\VMware",
            "SYSTEM\\ControlSet001\\Services\\vmci",
            "SYSTEM\\ControlSet001\\Services\\vmhgfs",
            "SYSTEM\\ControlSet001\\Services\\vmmouse",
            "SYSTEM\\ControlSet001\\Services\\vmrawdsk",
            "SYSTEM\\ControlSet001\\Services\\vmusbmouse",
            "SYSTEM\\ControlSet001\\Services\\vmvss",
            "SYSTEM\\ControlSet001\\Services\\vmscsi",
            "SYSTEM\\ControlSet001\\Services\\vmxnet"
        ],
        
        # File paths
        "files": [
            "C:\\Program Files\\VMware\\VMware Tools\\",
            "C:\\Program Files\\VMware\\",
            "C:\\windows\\system32\\drivers\\vmci.sys",
            "C:\\windows\\system32\\drivers\\vmhgfs.sys",
            "C:\\windows\\system32\\drivers\\vmmouse.sys",
            "C:\\windows\\system32\\drivers\\vmrawdsk.sys",
            "C:\\windows\\system32\\drivers\\vmusbmouse.sys",
            "C:\\windows\\system32\\drivers\\vmvss.sys",
            "C:\\windows\\system32\\drivers\\vmscsi.sys",
            "C:\\windows\\system32\\drivers\\vmxnet.sys",
            "C:\\windows\\system32\\drivers\\vmx86.sys",
            "C:\\windows\\system32\\drivers\\vmnetuserif.sys"
        ],
        
        # Process names
        "processes": [
            "vmware.exe", "vmwareuser.exe", "vmwaretray.exe", "vmwareservice.exe",
            "vmount2.exe", "vmware-vmx.exe", "vmware-hostd.exe", "vmware-authd.exe"
        ],
        
        # Hardware/BIOS strings (VMware specific only)
        "hardware": [
            "vmware", "vmware, inc.", "vmware virtual platform", "vmware virtual",
            "vmware-42", "vmware-56", "42 00 00 00 56 4d 58 68"  # VMXh magic
        ],
        
        # MAC address prefixes (VMware)
        "mac_prefixes": ["00:0C:29", "00:1C:14", "00:50:56"]
    }
    
    # VirtualBox detection artifacts
    VBOX_ARTIFACTS = {
        "registry_keys": [
            "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
            "SOFTWARE\\Oracle\\VirtualBox",
            "HARDWARE\\ACPI\\DSDT\\VBOX__",
            "HARDWARE\\ACPI\\FADT\\VBOX__",
            "HARDWARE\\ACPI\\RSDT\\VBOX__",
            "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
            "SYSTEM\\ControlSet001\\Services\\VBoxMouse",
            "SYSTEM\\ControlSet001\\Services\\VBoxService",
            "SYSTEM\\ControlSet001\\Services\\VBoxSF",
            "SYSTEM\\ControlSet001\\Services\\VBoxVideo"
        ],
        
        "files": [
            "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\",
            "C:\\windows\\system32\\drivers\\VBoxGuest.sys",
            "C:\\windows\\system32\\drivers\\VBoxMouse.sys",
            "C:\\windows\\system32\\drivers\\VBoxSF.sys",
            "C:\\windows\\system32\\drivers\\VBoxVideo.sys",
            "C:\\windows\\system32\\VBoxService.exe",
            "C:\\windows\\system32\\VBoxTray.exe",
            "C:\\windows\\system32\\VBoxHook.dll",
            "C:\\windows\\system32\\VBoxDisp.dll"
        ],
        
        "processes": [
            "VBoxService.exe", "VBoxTray.exe", "VBoxClient.exe"
        ],
        
        "hardware": [
            "virtualbox", "vbox", "innotek", "innotek gmbh", "oracle",
            "vboxvideo", "vboxguest", "oracle vm virtualbox"
        ],
        
        "mac_prefixes": ["08:00:27"]
    }
    
    # Hyper-V detection artifacts
    HYPERV_ARTIFACTS = {
        "registry_keys": [
            "SOFTWARE\\Microsoft\\Hyper-V",
            "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
            "SYSTEM\\ControlSet001\\Services\\vmbus",
            "SYSTEM\\ControlSet001\\Services\\VMBusHID",
            "SYSTEM\\ControlSet001\\Services\\hyperkbd",
            "SYSTEM\\ControlSet001\\Services\\hypermouse"
        ],
        
        "files": [
            "C:\\windows\\system32\\drivers\\vmbus.sys",
            "C:\\windows\\system32\\drivers\\VMBusHID.sys",
            "C:\\windows\\system32\\drivers\\hyperkbd.sys",
            "C:\\windows\\system32\\drivers\\hypermouse.sys"
        ],
        
        "processes": [
            "vmms.exe", "vmwp.exe"
        ],
        
        "hardware": [
            "microsoft corporation", "hyper-v", "virtual machine"
        ]
    }
    
    # QEMU detection artifacts
    QEMU_ARTIFACTS = {
        "registry_keys": [
            "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\\Identifier",
            "HARDWARE\\DESCRIPTION\\System\\SystemBiosInformation\\SystemManufacturer"
        ],
        
        "files": [
            "C:\\Program Files\\qemu-ga\\",
            "C:\\windows\\system32\\drivers\\qemu"
        ],
        
        "processes": [
            "qemu-ga.exe", "qemu-system-x86_64.exe"
        ],
        
        "hardware": [
            "qemu", "bochs", "seabios"
        ],
        
        "mac_prefixes": ["52:54:00"]
    }
    
    # VM detection APIs commonly used
    # More selective VM detection APIs - only truly suspicious ones
    VM_DETECTION_APIS = {
        # Hardware fingerprinting APIs (moderate suspicion)
        "moderate_suspicion": {
            "SetupDiGetClassDevs": 0.60,
            "SetupDiEnumDeviceInfo": 0.60, 
            "SetupDiGetDeviceRegistryProperty": 0.65,
            "GetAdaptersInfo": 0.55,
            "GetIfTable": 0.55,
            "GetIpAddrTable": 0.55,
        },
        
        # WMI APIs (high suspicion when combined)
        "high_suspicion": {
            "CoCreateInstance": 0.40,  # Very common, only suspicious in combination
            "IWbemServices": 0.75,     # More specific to WMI queries
        },
        
        # Note: Timing APIs moved to AntiDebugDetector to avoid overlap
        # QueryPerformanceCounter, GetTickCount etc are now handled by AntiDebugDetector
    }
    
    # Suspicious WMI queries for VM detection
    WMI_VM_QUERIES = [
        "SELECT * FROM Win32_ComputerSystem",
        "SELECT * FROM Win32_BIOS", 
        "SELECT * FROM Win32_BaseBoard",
        "SELECT * FROM Win32_SystemEnclosure",
        "SELECT * FROM Win32_Processor",
        "SELECT * FROM Win32_PnPEntity",
        "SELECT * FROM Win32_NetworkAdapter",
        "SELECT * FROM Win32_LogicalDisk",
        "SELECT * FROM Win32_VideoController",
        "SELECT * FROM Win32_TemperatureProbe",
        "SELECT * FROM MSAcpi_ThermalZoneTemperature"
    ]
    
    # CPU ID patterns that indicate virtualization
    CPU_PATTERNS = {
        "GenuineIntel": ["KVMKVMKVM", "Microsoft Hv", "VMwareVMware", "XenVMMXenVMM"],
        "AuthenticAMD": ["KVMKVMKVM", "Microsoft Hv", "VMwareVMware"]
    }
    
    # Time-based detection patterns (reduced to avoid overlap with AntiDebugDetector)
    TIMING_DETECTION_APIS = {
        "GetSystemTimeAsFileTime", "NtQuerySystemTime", "RtlQueryPerformanceCounter", "NtDelayExecution"
    }
    
    def __init__(self):
        super().__init__("VMDetector", "Detects virtual machine evasion techniques")
    
    def analyze(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """
        Main analysis method - coordinates all VM detection techniques
        """
        monitor.set_message("Analyzing VM evasion techniques...")
        
        # VM-specific artifact detection
        self._detect_vmware_artifacts(context, monitor)
        if monitor.is_cancelled(): return
        
        self._detect_vbox_artifacts(context, monitor)
        if monitor.is_cancelled(): return
        
        self._detect_hyperv_artifacts(context, monitor)
        if monitor.is_cancelled(): return
        
        self._detect_qemu_artifacts(context, monitor)
        if monitor.is_cancelled(): return
        
        # Generic VM detection techniques
        self._detect_vm_apis(context, monitor)
        if monitor.is_cancelled(): return
        
        self._detect_wmi_queries(context, monitor)
        if monitor.is_cancelled(): return
        
        self._detect_hardware_fingerprinting(context, monitor)
        if monitor.is_cancelled(): return
        
        self._detect_timing_evasion(context, monitor)
        if monitor.is_cancelled(): return
        
        self._detect_mac_address_checks(context, monitor)
        if monitor.is_cancelled(): return
        
        self._detect_cpu_detection(context, monitor)
        if monitor.is_cancelled(): return
        
        self._analyze_vm_behavior_patterns(context, monitor)
    
    def _detect_vmware_artifacts(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect VMware-specific artifacts"""
        monitor.set_message("Checking VMware artifacts...")
        self._detect_vm_artifacts(context, monitor, "VMware", self.VMWARE_ARTIFACTS)
    
    def _detect_vbox_artifacts(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect VirtualBox-specific artifacts"""  
        monitor.set_message("Checking VirtualBox artifacts...")
        self._detect_vm_artifacts(context, monitor, "VirtualBox", self.VBOX_ARTIFACTS)
    
    def _detect_hyperv_artifacts(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect Hyper-V artifacts"""
        monitor.set_message("Checking Hyper-V artifacts...")
        self._detect_vm_artifacts(context, monitor, "Hyper-V", self.HYPERV_ARTIFACTS)
    
    def _detect_qemu_artifacts(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect QEMU artifacts"""
        monitor.set_message("Checking QEMU artifacts...")
        self._detect_vm_artifacts(context, monitor, "QEMU", self.QEMU_ARTIFACTS)
    
    def _detect_vm_artifacts(self, context: AnalysisContext, monitor: TaskMonitor,
                           vm_name: str, artifacts: Dict[str, List[str]]) -> None:
        """Generic method to detect VM artifacts"""
        if context.file_data is None:
            return

        # Keep track of already detected strings to avoid duplicates
        detected_strings = set()

        try:
            file_str = context.file_data.decode('latin1', errors='ignore').lower()
            
            # Check registry keys
            for reg_key in artifacts.get("registry_keys", []):
                if monitor.is_cancelled(): return
                
                if reg_key.lower() in file_str and reg_key.lower() not in detected_strings:
                    detected_strings.add(reg_key.lower())
                    offset = file_str.find(reg_key.lower())

                    # Calculate confidence based on specificity of registry key
                    reg_confidence = 0.95 if "Guest Additions" in reg_key else 0.85

                    self.log_detection(
                        context=context,
                        technique=f"{vm_name} Registry Detection",
                        description=f"{vm_name} registry key reference: {reg_key}",
                        address=offset,
                        confidence=reg_confidence,
                        evidence=f"Registry key reference: {reg_key}",
                        vm_type=vm_name,
                        registry_key=reg_key,
                        detection_type="registry"
                    )
            
            # Check file paths
            for file_path in artifacts.get("files", []):
                if monitor.is_cancelled(): return
                
                if file_path.lower() in file_str and file_path.lower() not in detected_strings:
                    detected_strings.add(file_path.lower())
                    offset = file_str.find(file_path.lower())
                    
                    # File path confidence - higher for specific tools/drivers
                    file_confidence = 0.90 if any(x in file_path.lower() for x in ["guest", "tools", "additions"]) else 0.80

                    self.log_detection(
                        context=context,
                        technique=f"{vm_name} File Detection",
                        description=f"{vm_name} file path reference: {file_path}",
                        address=offset,
                        confidence=file_confidence,
                        evidence=f"File path reference: {file_path}",
                        vm_type=vm_name,
                        file_path=file_path,
                        detection_type="file_path"
                    )
            
            # Check process names
            for process in artifacts.get("processes", []):
                if monitor.is_cancelled(): return
                
                if process.lower() in file_str and process.lower() not in detected_strings:
                    detected_strings.add(process.lower())
                    offset = file_str.find(process.lower())
                    
                    # Process confidence - higher for specific VM processes
                    process_confidence = 0.95 if any(x in process.lower() for x in ["vmware", "vbox"]) else 0.85

                    self.log_detection(
                        context=context,
                        technique=f"{vm_name} Process Detection",
                        description=f"{vm_name} process name reference: {process}",
                        address=offset,
                        confidence=process_confidence,
                        evidence=f"Process name reference: {process}",
                        vm_type=vm_name,
                        process_name=process,
                        detection_type="process"
                    )
            
            # Check hardware strings
            for hardware in artifacts.get("hardware", []):
                if monitor.is_cancelled(): return
                
                if hardware.lower() in file_str and hardware.lower() not in detected_strings:
                    detected_strings.add(hardware.lower())
                    offset = file_str.find(hardware.lower())
                    
                    # Hardware confidence - very high for specific vendor strings
                    hardware_confidence = 0.98 if "inc." in hardware.lower() or "platform" in hardware.lower() else 0.88

                    self.log_detection(
                        context=context,
                        technique=f"{vm_name} Hardware Detection",
                        description=f"{vm_name} hardware string: {hardware}",
                        address=offset,
                        confidence=hardware_confidence,
                        evidence=f"Hardware identification string: {hardware}",
                        vm_type=vm_name,
                        hardware_string=hardware,
                        detection_type="hardware"
                    )
            
        except Exception:
            pass
    
    def _detect_vm_apis(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect VM detection API usage"""
        monitor.set_message("Checking VM detection APIs...")
        
        vm_api_count = 0
        detected_apis = []
        
        total_vm_score = 0.0
        high_suspicion_apis = []
        
        # Check each category of APIs
        for category, apis in self.VM_DETECTION_APIS.items():
            if monitor.is_cancelled(): return
            
            for api_name, confidence in apis.items():
                if context.has_import(api_name):
                    detected_apis.append(api_name)
                    total_vm_score += confidence
                    
                    import_info = context.get_import_by_name(api_name)
                    address = import_info.get('address', 0) if import_info else 0
                    
                    # Only log individual APIs with high suspicion
                    if confidence >= 0.60:
                        high_suspicion_apis.append(api_name)
                        self.log_detection(
                            context=context,
                            technique="VM Detection API",
                            description=f"Suspicious VM detection API: {api_name}",
                            address=address,
                            confidence=confidence,
                            evidence=f"Import of {api_name} - commonly used for hardware fingerprinting/VM detection",
                            api_name=api_name,
                            detection_type="suspicious_api_import"
                        )
        
        # Only flag if significant VM detection API usage (multiple APIs with combined suspicion)
        if total_vm_score >= 1.5 and len(detected_apis) >= 3:
            combined_confidence = min(total_vm_score / len(detected_apis), 0.95)
            self.log_detection(
                context=context,
                technique="VM Timing Detection",
                description=f"Timing-based VM detection pattern ({len(detected_apis)} APIs)",
                address=0,
                confidence=combined_confidence,
                evidence=f"Combined VM detection API usage score: {total_vm_score:.2f}",
                api_count=len(detected_apis),
                vm_score=total_vm_score,
                apis_sample=detected_apis[:5],
                detection_type="timing_vm_detection"
            )
    
    def _detect_wmi_queries(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect WMI queries used for VM detection"""
        monitor.set_message("Analyzing WMI queries...")
        
        if context.file_data is None:
            return
        
        try:
            file_str = context.file_data.decode('latin1', errors='ignore')
            
            wmi_detections = 0
            for query in self.WMI_VM_QUERIES:
                if monitor.is_cancelled(): return
                
                if query.lower() in file_str.lower():
                    offset = file_str.lower().find(query.lower())
                    wmi_detections += 1
                    
                    # WMI query confidence based on specificity
                    wmi_confidence = 0.85 if any(x in query for x in ["BIOS", "ComputerSystem", "BaseBoard"]) else 0.75

                    self.log_detection(
                        context=context,
                        technique="WMI VM Detection Query",
                        description=f"WMI query for VM detection: {query}",
                        address=offset,
                        confidence=wmi_confidence,
                        evidence=f"WMI query: {query}",
                        wmi_query=query,
                        detection_type="wmi_query"
                    )
            
            # Multiple WMI queries increase suspicion
            if wmi_detections >= 3:
                multiple_confidence = min(0.70 + (wmi_detections * 0.05), 0.95)

                self.log_detection(
                    context=context,
                    technique="Multiple WMI VM Queries",
                    description=f"Multiple WMI queries for VM detection ({wmi_detections})",
                    address=0,
                    confidence=multiple_confidence,
                    evidence=f"Found {wmi_detections} WMI queries commonly used for VM detection",
                    wmi_query_count=wmi_detections,
                    detection_type="multiple_wmi_queries"
                )
        except Exception:
            pass
    
    def _detect_hardware_fingerprinting(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect hardware fingerprinting for VM detection"""
        monitor.set_message("Checking hardware fingerprinting...")
        
        # Check for hardware-related API imports
        hardware_apis = {
            "GetSystemInfo", "GlobalMemoryStatusEx", "GetAdaptersInfo",
            "SetupDiGetClassDevs", "SetupDiEnumDeviceInfo", "GetVolumeInformationA",
            "GetDiskFreeSpaceExA", "DeviceIoControl", "GetSystemMetrics"
        }
        
        hardware_api_count = 0
        for api_name in hardware_apis:
            if monitor.is_cancelled(): return
            
            if context.has_import(api_name):
                hardware_api_count += 1
                import_info = context.get_import_by_name(api_name)
                address = import_info.get('address', 0) if import_info else 0
                
                self.log_detection(
                    context=context,
                    technique="Hardware Fingerprinting API",
                    description=f"Hardware fingerprinting API: {api_name}",
                    address=address,
                                        evidence=f"Import of {api_name} - used for hardware fingerprinting",
                    api_name=api_name,
                    detection_type="hardware_api"
                )
        
        # Multiple hardware APIs suggest comprehensive fingerprinting
        if hardware_api_count >= 4:
            self.log_detection(
                context=context,
                technique="Comprehensive Hardware Fingerprinting",
                description=f"Comprehensive hardware fingerprinting ({hardware_api_count} APIs)",
                address=0,
                                evidence=f"Using {hardware_api_count} hardware APIs for environment detection",
                hardware_api_count=hardware_api_count,
                detection_type="hardware_fingerprinting"
            )
    
    def _detect_timing_evasion(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect timing-based VM evasion"""
        monitor.set_message("Analyzing timing evasion techniques...")
        
        timing_api_count = 0
        for api_name in self.TIMING_DETECTION_APIS:
            if monitor.is_cancelled(): return
            
            if context.has_import(api_name):
                timing_api_count += 1
                import_info = context.get_import_by_name(api_name)
                address = import_info.get('address', 0) if import_info else 0
                
                self.log_detection(
                    context=context,
                    technique="VM Timing Detection",
                    description=f"Timing API for VM detection: {api_name}",
                    address=address,
                                        evidence=f"Import of {api_name} - may be used for VM timing detection",
                    api_name=api_name,
                    detection_type="timing_api"
                )
        
        # Multiple timing APIs suggest timing-based evasion
        if timing_api_count >= 3:
            self.log_detection(
                context=context,
                technique="VM Timing Evasion",
                description=f"Multiple timing APIs for VM detection ({timing_api_count} APIs)",
                address=0,
                                evidence=f"Using {timing_api_count} timing APIs - possible VM evasion via timing",
                timing_api_count=timing_api_count,
                detection_type="timing_evasion"
            )
    
    def _detect_mac_address_checks(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect MAC address checks for VM detection"""
        monitor.set_message("Checking MAC address detection...")
        
        if context.file_data is None:
            return
        
        # Collect all MAC prefixes
        all_mac_prefixes = []
        for vm_artifacts in [self.VMWARE_ARTIFACTS, self.VBOX_ARTIFACTS, self.QEMU_ARTIFACTS]:
            all_mac_prefixes.extend(vm_artifacts.get("mac_prefixes", []))
        
        try:
            file_str = context.file_data.decode('latin1', errors='ignore')
            
            for mac_prefix in all_mac_prefixes:
                if monitor.is_cancelled(): return
                
                # Check both with and without colons/dashes
                mac_variants = [
                    mac_prefix,
                    mac_prefix.replace(":", ""),
                    mac_prefix.replace(":", "-"),
                    mac_prefix.replace(":", "").lower(),
                    mac_prefix.replace(":", "-").upper()
                ]
                
                for variant in mac_variants:
                    if variant.lower() in file_str.lower():
                        offset = file_str.lower().find(variant.lower())
                        
                        self.log_detection(
                            context=context,
                            technique="VM MAC Address Detection",
                            description=f"VM MAC address prefix check: {mac_prefix}",
                            address=offset,
                                                        evidence=f"MAC address prefix: {mac_prefix} (VM indicator)",
                            mac_prefix=mac_prefix,
                            detection_type="mac_address"
                        )
                        break  # Avoid duplicate detections
        except Exception:
            pass
    
    def _detect_cpu_detection(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Detect CPU-based VM detection techniques"""
        monitor.set_message("Analyzing CPU detection techniques...")
        
        if context.file_data is None:
            return
        
        try:
            file_str = context.file_data.decode('latin1', errors='ignore')
            
            # Check for CPUID-related strings
            cpuid_patterns = ["cpuid", "genuineintel", "authenticamd", "centaurhauls"]
            
            for pattern in cpuid_patterns:
                if monitor.is_cancelled(): return
                
                if pattern in file_str.lower():
                    offset = file_str.lower().find(pattern)
                    
                    self.log_detection(
                        context=context,
                        technique="CPU Detection",
                        description=f"CPU identification pattern: {pattern}",
                        address=offset,
                                                evidence=f"CPU pattern: {pattern}",
                        cpu_pattern=pattern,
                        detection_type="cpu_detection"
                    )
            
            # Check for hypervisor detection strings
            for vendor, hypervisors in self.CPU_PATTERNS.items():
                for hypervisor in hypervisors:
                    if monitor.is_cancelled(): return
                    
                    if hypervisor.lower() in file_str.lower():
                        offset = file_str.lower().find(hypervisor.lower())
                        
                        self.log_detection(
                            context=context,
                            technique="Hypervisor Detection",
                            description=f"Hypervisor signature check: {hypervisor}",
                            address=offset,
                                                        evidence=f"Hypervisor signature: {hypervisor}",
                            cpu_vendor=vendor,
                            hypervisor_signature=hypervisor,
                            detection_type="hypervisor_detection"
                        )
        except Exception:
            pass
    
    def _analyze_vm_behavior_patterns(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """Analyze behavioral patterns that suggest VM evasion"""
        monitor.set_message("Analyzing VM behavior patterns...")
        
        # Count total VM-related detections
        vm_detections = len([r for r in context.get_results() if "VM" in r.technique_name or "Virtual" in r.technique_name])
        
        if vm_detections >= 5:
            self.log_detection(
                context=context,
                technique="Comprehensive VM Evasion",
                description=f"Comprehensive VM evasion detected ({vm_detections} techniques)",
                address=0,
                                evidence=f"Multiple VM evasion techniques detected: {vm_detections} different methods",
                vm_detection_count=vm_detections,
                detection_type="comprehensive_evasion"
            )
    
    def get_supported_techniques(self) -> List[str]:
        """Get list of supported detection techniques"""
        return [
            "VMware Registry Detection",
            "VMware File Detection", 
            "VMware Process Detection",
            "VMware Hardware Detection",
            "VirtualBox Registry Detection",
            "VirtualBox File Detection",
            "VirtualBox Process Detection", 
            "VirtualBox Hardware Detection",
            "Hyper-V Registry Detection",
            "Hyper-V File Detection",
            "Hyper-V Process Detection",
            "Hyper-V Hardware Detection",
            "QEMU Registry Detection",
            "QEMU File Detection",
            "QEMU Process Detection",
            "QEMU Hardware Detection",
            "VM Detection API",
            "Multiple VM Detection APIs",
            "WMI VM Detection Query",
            "Multiple WMI VM Queries",
            "Hardware Fingerprinting API",
            "Comprehensive Hardware Fingerprinting",
            "VM Timing Detection",
            "VM Timing Evasion",
            "VM MAC Address Detection",
            "CPU Detection",
            "Hypervisor Detection",
            "Comprehensive VM Evasion"
        ]
    
    def get_vm_types(self) -> List[str]:
        """Get list of detected VM types"""
        return ["VMware", "VirtualBox", "Hyper-V", "QEMU"]


# Example usage and testing
if __name__ == "__main__":
    from core.analysis_context import AnalysisContext
    from core.base_detector import TaskMonitor
    
    # Test the detector
    detector = VMDetector()
    print(f"Detector: {detector}")
    print(f"Supported techniques: {detector.get_supported_techniques()}")
    print(f"VM types: {detector.get_vm_types()}")
    
    # This would be used with actual binary analysis
    # context = AnalysisContext("vm_evasion_sample.exe")
    # monitor = TaskMonitor()  
    # detector.analyze(context, monitor)
"""
Binary Parser per CONAN Framework
Gestisce file PE, ELF e altri formati binari usando pefile e LIEF come fallback
"""

import os
import hashlib
import struct
import logging
from typing import Dict, List, Any, Optional, Union
from pathlib import Path


class BinaryInfo:
    """
    Contenitore per le informazioni estratte da un binario.
    
    Contiene tutti i metadati necessari per l'analisi CONAN:
    - Informazioni base del file (tipo, dimensione, architettura)
    - Hash di sicurezza (MD5, SHA1, SHA256)  
    - Struttura interna (sezioni, entry point, image base)
    - Tabelle import/export per API analysis
    - Dati raw per analisi avanzata
    """
    
    def __init__(self):
        # Informazioni base del file
        self.file_path: str = ""
        self.file_size: int = 0
        self.file_type: str = "unknown"  # PE, ELF, Mach-O, unknown
        self.architecture: str = "unknown"  # x86, x64, arm, etc.
        self.subsystem: str = "unknown"  # console, gui, driver, etc.
        
        # Punti di ingresso e indirizzi base
        self.entry_point: int = 0
        self.image_base: int = 0
        
        # Hash di sicurezza per identificazione malware
        self.md5: str = ""
        self.sha1: str = ""
        self.sha256: str = ""
        
        # Struttura interna del binario
        self.sections: List[Dict[str, Any]] = []
        
        # Tabelle import/export per API analysis
        self.imports: List[Dict[str, Any]] = []
        self.exports: List[Dict[str, Any]] = []
        
        # Dati raw per analisi approfondita
        self.raw_data: Optional[bytes] = None
        
        # Metadati PE specifici
        self.timestamp: Optional[int] = None
        self.checksum: Optional[int] = None
        self.pe_characteristics: Optional[int] = None


def calcola_hash_file(data: bytes) -> Dict[str, str]:
    """
    Calcola gli hash di sicurezza per identificazione malware.
    
    Args:
        data: Dati raw del file
        
    Returns:
        Dict con MD5, SHA1, SHA256 in formato esadecimale lowercase
    """
    return {
        'md5': hashlib.md5(data).hexdigest().lower(),
        'sha1': hashlib.sha1(data).hexdigest().lower(), 
        'sha256': hashlib.sha256(data).hexdigest().lower()
    }


def rileva_tipo_file(data: bytes) -> str:
    """
    Rileva il tipo di file dai magic bytes.
    
    Args:
        data: Prime centinaia di byte del file
        
    Returns:
        Stringa identificativa del tipo: PE, ELF, Mach-O, unknown
    """
    if len(data) < 4:
        return "unknown"
    
    # PE (Windows Portable Executable)
    if data.startswith(b'MZ'):
        return "PE"
    
    # ELF (Linux/Unix Executable and Linkable Format) 
    elif data.startswith(b'\x7fELF'):
        return "ELF"
    
    # Mach-O (macOS)
    elif data.startswith(b'\xfe\xed\xfa\xce') or data.startswith(b'\xce\xfa\xed\xfe'):
        return "Mach-O"
    
    # Formato sconosciuto
    else:
        return "unknown"


def parse_binary_semplice(file_path: str) -> BinaryInfo:
    """
    Parser binario semplificato senza dipendenze esterne.
    
    Questo è il fallback quando pefile/LIEF non sono disponibili.
    Implementa un parsing manuale basilare per PE e ELF.
    
    Args:
        file_path: Percorso al file binario
        
    Returns:
        BinaryInfo con informazioni base estratte
    """
    info = BinaryInfo()
    info.file_path = file_path
    
    try:
        # Leggi il file completo
        with open(file_path, 'rb') as f:
            data = f.read()
        
        info.raw_data = data
        info.file_size = len(data)
        
        # Calcola hash di sicurezza
        hashes = calcola_hash_file(data)
        info.md5 = hashes['md5']
        info.sha1 = hashes['sha1']
        info.sha256 = hashes['sha256']
        
        # Rileva tipo di file
        info.file_type = rileva_tipo_file(data)
        
        # Parsing specifico per tipo
        if info.file_type == "PE":
            _parse_pe_manuale(info, data)
        elif info.file_type == "ELF":
            _parse_elf_manuale(info, data)
        else:
            # File sconosciuto - imposta valori di default
            info.architecture = "unknown"
            info.entry_point = 0
        
    except Exception as e:
        logging.error(f"Errore durante parsing semplice di {file_path}: {e}")
        # Continua comunque - le info base sono già state impostate
    
    return info


def _parse_pe_manuale(info: BinaryInfo, data: bytes) -> None:
    """
    Parsing manuale di file PE (Portable Executable).
    
    Estrae le informazioni essenziali senza dipendenze esterne:
    - Architettura (x86/x64)
    - Entry point e image base
    - Sezioni principali
    - Import table semplificata
    
    Args:
        info: Oggetto BinaryInfo da popolare
        data: Dati raw del file PE
    """
    try:
        # Verifica header MZ
        if len(data) < 0x40 or data[:2] != b'MZ':
            return
        
        # Ottieni offset dell'header PE
        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
        
        # Verifica che l'offset sia valido
        if pe_offset >= len(data) - 24:
            return
        
        # Verifica signature PE
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return
        
        # Leggi COFF header
        coff_header = data[pe_offset+4:pe_offset+24]
        machine, num_sections, timestamp = struct.unpack('<HHI', coff_header[:8])
        
        # Determina architettura dalla machine type
        if machine == 0x014c:  # IMAGE_FILE_MACHINE_I386
            info.architecture = "x86"
        elif machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64  
            info.architecture = "x64"
        elif machine == 0x01c0:  # IMAGE_FILE_MACHINE_ARM
            info.architecture = "arm"
        elif machine == 0xaa64:  # IMAGE_FILE_MACHINE_ARM64
            info.architecture = "arm64"
        else:
            info.architecture = f"unknown_0x{machine:04x}"
        
        info.timestamp = timestamp
        
        # Leggi Optional Header per entry point e image base
        optional_header_size = struct.unpack('<H', coff_header[16:18])[0]
        if optional_header_size > 0 and pe_offset + 24 + optional_header_size <= len(data):
            optional_header = data[pe_offset+24:pe_offset+24+optional_header_size]
            
            if len(optional_header) >= 28:
                # Entry point e image base sono sempre nelle stesse posizioni
                info.entry_point = struct.unpack('<I', optional_header[16:20])[0]
                info.image_base = struct.unpack('<I', optional_header[28:32])[0]
                
                # Subsystem (GUI vs Console)
                if len(optional_header) >= 68:
                    subsystem = struct.unpack('<H', optional_header[68:70])[0]
                    if subsystem == 2:
                        info.subsystem = "gui" 
                    elif subsystem == 3:
                        info.subsystem = "console"
                    elif subsystem == 1:
                        info.subsystem = "driver"
                    else:
                        info.subsystem = f"unknown_{subsystem}"
        
        # Parse sezioni (semplificato)
        section_table_offset = pe_offset + 24 + optional_header_size
        _parse_pe_sections_manuale(info, data, section_table_offset, num_sections)
        
        # Cerca import semplificati (scanning per string comuni)
        _find_api_strings_semplificato(info, data)
        
    except Exception as e:
        logging.warning(f"Errore parsing PE manuale: {e}")


def _parse_pe_sections_manuale(info: BinaryInfo, data: bytes, section_offset: int, num_sections: int) -> None:
    """
    Parse manuale delle sezioni PE.
    
    Args:
        info: BinaryInfo da popolare
        data: Dati raw del file
        section_offset: Offset della section table
        num_sections: Numero di sezioni
    """
    try:
        for i in range(num_sections):
            # Ogni entry della section table è 40 byte
            entry_offset = section_offset + i * 40
            if entry_offset + 40 > len(data):
                break
            
            # Leggi section header
            section_header = data[entry_offset:entry_offset+40]
            
            # Nome sezione (8 byte, null-padded)
            name_bytes = section_header[0:8]
            name = name_bytes.split(b'\x00')[0].decode('utf-8', errors='ignore')
            
            # Offset e dimensioni
            virtual_size = struct.unpack('<I', section_header[8:12])[0]
            virtual_address = struct.unpack('<I', section_header[12:16])[0] 
            raw_size = struct.unpack('<I', section_header[16:20])[0]
            raw_address = struct.unpack('<I', section_header[20:24])[0]
            
            # Caratteristiche (permissions)
            characteristics = struct.unpack('<I', section_header[36:40])[0]
            
            section_info = {
                'name': name,
                'virtual_address': virtual_address,
                'virtual_size': virtual_size,
                'raw_address': raw_address,
                'raw_size': raw_size,
                'executable': bool(characteristics & 0x20000000),  # IMAGE_SCN_MEM_EXECUTE
                'readable': bool(characteristics & 0x40000000),    # IMAGE_SCN_MEM_READ
                'writable': bool(characteristics & 0x80000000),    # IMAGE_SCN_MEM_WRITE
                'characteristics': characteristics
            }
            
            info.sections.append(section_info)
            
    except Exception as e:
        logging.warning(f"Errore parsing sezioni PE: {e}")


def _parse_elf_manuale(info: BinaryInfo, data: bytes) -> None:
    """
    Parsing manuale basilare per file ELF.
    
    Args:
        info: BinaryInfo da popolare  
        data: Dati raw del file ELF
    """
    try:
        if len(data) < 16:
            return
        
        # ELF header: e_ident[16], e_type[2], e_machine[2], e_version[4], e_entry[4/8]
        ei_class = data[4]  # 1=32bit, 2=64bit
        ei_data = data[5]   # 1=little endian, 2=big endian
        
        # Determina architettura  
        if ei_class == 1:
            info.architecture = "x86"
        elif ei_class == 2:
            info.architecture = "x64"
        else:
            info.architecture = "unknown"
        
        # Entry point (offset diverso per 32/64 bit)
        if ei_class == 1:  # 32-bit
            if len(data) >= 28:
                info.entry_point = struct.unpack('<I' if ei_data == 1 else '>I', data[24:28])[0]
        else:  # 64-bit
            if len(data) >= 32:
                info.entry_point = struct.unpack('<Q' if ei_data == 1 else '>Q', data[24:32])[0]
        
    except Exception as e:
        logging.warning(f"Errore parsing ELF manuale: {e}")


def _find_api_strings_semplificato(info: BinaryInfo, data: bytes) -> None:
    """
    Cerca string di API comuni nel binario per simulare import table.
    
    Questo è un approccio semplificato quando non possiamo parsare 
    la vera import table.
    
    Args:
        info: BinaryInfo da popolare con import fittizi
        data: Dati raw del file
    """
    # API comuni per anti-debug, VM detection, etc.
    api_comuni = [
        # Anti-debug APIs
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugStringA", "OutputDebugStringW", "GetThreadContext", "SetThreadContext",
        
        # Timing APIs  
        "QueryPerformanceCounter", "GetTickCount", "GetTickCount64", "timeGetTime",
        
        # VM detection APIs
        "SetupDiGetClassDevs", "SetupDiEnumDeviceInfo", "GetAdaptersInfo",
        
        # Processo/thread APIs
        "CreateThread", "CreateProcess", "OpenProcess", "TerminateProcess",
        
        # File I/O
        "CreateFile", "ReadFile", "WriteFile", "DeleteFile",
        
        # Registry
        "RegOpenKey", "RegQueryValue", "RegSetValue", "RegCreateKey",
        
        # Network
        "WSAStartup", "socket", "connect", "send", "recv",
        
        # Crypto
        "CryptAcquireContext", "CryptGenRandom", "CryptEncrypt"
    ]
    
    try:
        # Converti data in stringa per ricerca più veloce
        data_lower = data.lower()
        
        for api in api_comuni:
            # Cerca sia ASCII che UTF-16LE
            api_ascii = api.encode('ascii', errors='ignore').lower()
            api_utf16 = api.encode('utf-16le', errors='ignore').lower()
            
            if api_ascii in data_lower or api_utf16 in data_lower:
                # Determina DLL più probabile (semplificato)
                dll = _indovina_dll_per_api(api)
                
                info.imports.append({
                    'name': api,
                    'library': dll,
                    'address': 0,  # Non possiamo determinarlo senza parsing completo
                    'ordinal': None
                })
                
    except Exception as e:
        logging.warning(f"Errore ricerca API strings: {e}")


def _indovina_dll_per_api(api_name: str) -> str:
    """
    Indovina la DLL più probabile per una data API.
    
    Args:
        api_name: Nome dell'API
        
    Returns:
        Nome della DLL più probabile
    """
    # Mapping semplificato API -> DLL
    mappings = {
        'kernel32.dll': ['CreateFile', 'ReadFile', 'WriteFile', 'CreateThread', 'GetTickCount', 
                        'IsDebuggerPresent', 'OutputDebugString', 'GetThreadContext'],
        'ntdll.dll': ['NtQueryInformationProcess', 'NtSetInformationThread'],
        'advapi32.dll': ['RegOpenKey', 'RegQueryValue', 'CryptAcquireContext'],
        'ws2_32.dll': ['WSAStartup', 'socket', 'connect', 'send', 'recv'],
        'setupapi.dll': ['SetupDiGetClassDevs', 'SetupDiEnumDeviceInfo'],
        'iphlpapi.dll': ['GetAdaptersInfo'],
        'winmm.dll': ['timeGetTime']
    }
    
    for dll, apis in mappings.items():
        if any(api in api_name for api in apis):
            return dll
    
    return 'unknown.dll'


def parse_binary_con_pefile(file_path: str) -> BinaryInfo:
    """
    Parser binario usando la libreria pefile (raccomandato per PE).
    
    Fornisce parsing completo e accurato dei file PE con:
    - Import/Export table complete
    - Sezioni dettagliate con permissions
    - Metadati PE approfonditi
    
    Args:
        file_path: Percorso al file PE
        
    Returns:
        BinaryInfo con informazioni complete
    """
    try:
        import pefile
    except ImportError:
        logging.warning("pefile non disponibile, usando parser semplice")
        return parse_binary_semplice(file_path)
    
    info = BinaryInfo()
    info.file_path = file_path
    
    try:
        # Leggi dati raw per hash
        with open(file_path, 'rb') as f:
            data = f.read()
        info.raw_data = data
        info.file_size = len(data)
        
        # Calcola hash
        hashes = calcola_hash_file(data)
        info.md5 = hashes['md5']
        info.sha1 = hashes['sha1'] 
        info.sha256 = hashes['sha256']
        
        # Parse con pefile
        pe = pefile.PE(file_path, fast_load=False)  # fast_load=False per import completi
        
        info.file_type = "PE"
        info.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        info.image_base = pe.OPTIONAL_HEADER.ImageBase
        info.timestamp = pe.FILE_HEADER.TimeDateStamp
        info.pe_characteristics = pe.FILE_HEADER.Characteristics
        
        # Determina architettura
        machine_types = {
            0x014c: "x86",      # IMAGE_FILE_MACHINE_I386
            0x8664: "x64",      # IMAGE_FILE_MACHINE_AMD64
            0x01c0: "arm",      # IMAGE_FILE_MACHINE_ARM
            0xaa64: "arm64"     # IMAGE_FILE_MACHINE_ARM64
        }
        info.architecture = machine_types.get(pe.FILE_HEADER.Machine, 
                                            f"unknown_0x{pe.FILE_HEADER.Machine:04x}")
        
        # Subsystem
        subsystem_types = {
            1: "native", 2: "gui", 3: "console", 7: "posix", 9: "ce_gui", 
            10: "efi_application", 11: "efi_boot_service_driver", 
            12: "efi_runtime_driver", 13: "efi_rom", 14: "xbox"
        }
        info.subsystem = subsystem_types.get(pe.OPTIONAL_HEADER.Subsystem, "unknown")
        
        # Parse sezioni
        for section in pe.sections:
            section_info = {
                'name': section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
                'virtual_address': section.VirtualAddress,
                'virtual_size': section.Misc_VirtualSize,
                'raw_address': section.PointerToRawData,
                'raw_size': section.SizeOfRawData,
                'executable': bool(section.Characteristics & 0x20000000),
                'readable': bool(section.Characteristics & 0x40000000),
                'writable': bool(section.Characteristics & 0x80000000),
                'characteristics': section.Characteristics,
                
                # Informazioni aggiuntive utili per CONAN
                'entropy': _calcola_entropia_sezione(pe, section) if section.SizeOfRawData > 0 else 0.0
            }
            info.sections.append(section_info)
        
        # Parse import table
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    
                    for imp in entry.imports:
                        import_info = {
                            'name': imp.name.decode('utf-8', errors='ignore') if imp.name else f"ord_{imp.ordinal}",
                            'library': dll_name,
                            'address': imp.address,
                            'ordinal': imp.ordinal
                        }
                        info.imports.append(import_info)
                        
                except Exception as e:
                    logging.debug(f"Errore parsing import da {entry.dll}: {e}")
                    continue
        
        # Parse export table
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    export_info = {
                        'name': exp.name.decode('utf-8', errors='ignore') if exp.name else f"ord_{exp.ordinal}",
                        'address': exp.address,
                        'ordinal': exp.ordinal
                    }
                    info.exports.append(export_info)
                except Exception as e:
                    logging.debug(f"Errore parsing export: {e}")
                    continue
        
        pe.close()
        
    except Exception as e:
        logging.error(f"Errore parsing PE con pefile {file_path}: {e}")
        # Fallback al parser semplice
        return parse_binary_semplice(file_path)
    
    return info


def _calcola_entropia_sezione(pe, section) -> float:
    """
    Calcola l'entropia di Shannon di una sezione PE.
    
    L'entropia alta (>7.0) può indicare packing/encryption.
    
    Args:
        pe: Oggetto pefile
        section: Sezione PE
        
    Returns:
        Entropia della sezione (0.0-8.0)
    """
    try:
        import math
        
        # Leggi dati sezione
        data = section.get_data()
        if len(data) == 0:
            return 0.0
        
        # Conta frequenza byte
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calcola entropia Shannon
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
        
    except Exception:
        return 0.0


def parse_binary(file_path: str) -> BinaryInfo:
    """
    Funzione principale per il parsing binario.
    
    Prova diversi parser in ordine di preferenza:
    1. pefile per file PE (più accurato)
    2. Parser semplice come fallback
    
    Args:
        file_path: Percorso al file binario da analizzare
        
    Returns:
        BinaryInfo con tutte le informazioni estratte
        
    Raises:
        FileNotFoundError: Se il file non esiste
        PermissionError: Se non si hanno i permessi di lettura
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File non trovato: {file_path}")
    
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Permessi insufficienti per leggere: {file_path}")
    
    # Determina tipo di file dai magic bytes
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
    except Exception as e:
        raise PermissionError(f"Impossibile leggere file: {e}")
    
    tipo_file = rileva_tipo_file(header)
    
    # Scegli parser appropriato
    if tipo_file == "PE":
        return parse_binary_con_pefile(file_path)
    else:
        # Per ELF e altri formati, usa parser semplice per ora
        # TODO: Implementare support LIEF per ELF/Mach-O
        return parse_binary_semplice(file_path)


def load_binary_into_context(context, binary_info: BinaryInfo) -> None:
    """
    Carica le informazioni del binario nel context di analisi CONAN.
    
    Trasferisce tutti i dati dalla BinaryInfo al context per l'uso
    da parte dei detector.
    
    Args:
        context: Context di analisi CONAN
        binary_info: Informazioni estratte dal binario
    """
    try:
        # Dati principali
        context.file_data = binary_info.raw_data
        context.architecture = binary_info.architecture  
        context.entry_point = binary_info.entry_point
        context.sections = binary_info.sections
        context.imports = binary_info.imports
        context.exports = binary_info.exports
        
        # Cache informazioni aggiuntive per i detector
        context.cache_value("file_size", binary_info.file_size)
        context.cache_value("file_type", binary_info.file_type)
        context.cache_value("image_base", binary_info.image_base)
        context.cache_value("subsystem", binary_info.subsystem)
        context.cache_value("timestamp", binary_info.timestamp)
        
        # Hash per identificazione
        context.cache_value("md5", binary_info.md5)
        context.cache_value("sha1", binary_info.sha1)  
        context.cache_value("sha256", binary_info.sha256)
        
        # Statistiche per detector
        context.cache_value("section_count", len(binary_info.sections))
        context.cache_value("import_count", len(binary_info.imports))
        context.cache_value("export_count", len(binary_info.exports))
        
        # Metadati PE specifici (se disponibili)
        if binary_info.pe_characteristics:
            context.cache_value("pe_characteristics", binary_info.pe_characteristics)
            context.cache_value("pe_checksum", binary_info.checksum)
        
        logging.info(f"Caricato {binary_info.file_type} ({binary_info.architecture}) "
                    f"con {len(binary_info.sections)} sezioni, "
                    f"{len(binary_info.imports)} import, {len(binary_info.exports)} export")
        
    except Exception as e:
        logging.error(f"Errore caricamento binary_info in context: {e}")
        # Non rilanciare - i detector possono comunque funzionare con dati parziali


# Test del parser se eseguito direttamente
if __name__ == "__main__":
    import sys
    
    # Configura logging per debug
    logging.basicConfig(level=logging.INFO, 
                       format='%(levelname)s: %(message)s')
    
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        try:
            print(f"Analizzando: {file_path}")
            info = parse_binary(file_path)
            
            print(f"\n=== INFORMAZIONI BINARIO ===")
            print(f"File: {info.file_path}")
            print(f"Tipo: {info.file_type}")
            print(f"Architettura: {info.architecture}")
            print(f"Subsystem: {info.subsystem}")
            print(f"Dimensione: {info.file_size:,} bytes")
            print(f"Entry Point: 0x{info.entry_point:08x}")
            print(f"Image Base: 0x{info.image_base:08x}")
            
            if info.timestamp:
                import datetime
                ts = datetime.datetime.fromtimestamp(info.timestamp)
                print(f"Timestamp: {ts} (0x{info.timestamp:x})")
            
            print(f"\n=== HASH ===")
            print(f"MD5: {info.md5}")
            print(f"SHA1: {info.sha1}")  
            print(f"SHA256: {info.sha256}")
            
            print(f"\n=== STRUTTURA ===")
            print(f"Sezioni: {len(info.sections)}")
            for section in info.sections[:10]:  # Prime 10 sezioni
                perms = ""
                if section['executable']: perms += "X"
                if section['readable']: perms += "R" 
                if section['writable']: perms += "W"
                
                entropy = section.get('entropy', 0.0)
                print(f"  {section['name']:<12} VA:0x{section['virtual_address']:08x} "
                      f"Size:0x{section['virtual_size']:06x} {perms:<3} Entropy:{entropy:.2f}")
            
            print(f"\nImport: {len(info.imports)}")
            if info.imports:
                print("  Prime 10 API importate:")
                for imp in info.imports[:10]:
                    print(f"    {imp['library']}!{imp['name']}")
            
            print(f"\nExport: {len(info.exports)}")
            if info.exports:
                print("  Prime 10 API esportate:")
                for exp in info.exports[:10]:
                    print(f"    {exp['name']} @ 0x{exp['address']:08x}")
                    
        except Exception as e:
            print(f"ERRORE: {e}")
            sys.exit(1)
    else:
        print("Uso: python binary_parser.py <percorso_file>")
        print("\nEsempio:")
        print("  python binary_parser.py C:\\Windows\\System32\\notepad.exe")
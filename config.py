"""
Configurazione del Framework CONAN
Configurazione centralizzata per il framework di rilevamento anti-reversing CONAN

Questo modulo contiene tutte le impostazioni e costanti utilizzate nel framework CONAN.
Include percorsi di progetto, impostazioni dell'applicazione, configurazioni GUI,
soglie di rilevamento e altre costanti necessarie per il funzionamento del sistema.
"""

import os
from pathlib import Path

# Percorsi del progetto - Definiscono la struttura delle directory del framework
PROJECT_ROOT = Path(__file__).parent  # Directory principale del progetto
CORE_DIR = PROJECT_ROOT / "core"       # Directory del motore di rilevamento principale
DETECTORS_DIR = PROJECT_ROOT / "detectors"  # Directory contenente i moduli rilevatori
GUI_DIR = PROJECT_ROOT / "gui"         # Directory dell'interfaccia grafica
UTILS_DIR = PROJECT_ROOT / "utils"     # Directory delle utility di supporto
SAMPLES_DIR = PROJECT_ROOT / "samples" # Directory dei file di esempio per test
DOCS_DIR = PROJECT_ROOT / "docs"       # Directory della documentazione
BUILD_DIR = PROJECT_ROOT / "build"     # Directory per i file di build

# Impostazioni dell'applicazione - Informazioni di base sul framework
APP_NAME = "CONAN"  # Nome dell'applicazione (COde aNalysis)
APP_VERSION = "2.0.0"  # Versione corrente del framework
APP_DESCRIPTION = "COde aNalysis Anti-reversing detectioN framework"  # Descrizione completa
APP_AUTHOR = "CONAN Team"  # Autore/Team di sviluppo

# Impostazioni dell'interfaccia grafica - Configurazioni per la GUI PyQt6
WINDOW_TITLE = f"{APP_NAME} v{APP_VERSION} - Framework di Rilevamento Anti-Reversing"
WINDOW_ICON = PROJECT_ROOT / "conanImmagine.png"  # Icona dell'applicazione (Detective Conan)
WINDOW_MIN_WIDTH = 1200   # Larghezza minima della finestra in pixel
WINDOW_MIN_HEIGHT = 800   # Altezza minima della finestra in pixel

# Impostazioni di rilevamento - Parametri per l'analisi anti-reversing
DEFAULT_CONFIDENCE_THRESHOLD = 0.6  # Soglia di confidenza predefinita (60%)
MAX_ANALYSIS_TIMEOUT = 300          # Timeout massimo analisi in secondi (5 minuti)
DEFAULT_DETECTORS = [               # Lista dei rilevatori abilitati di default
    "AntiDebugDetector",            # Rilevatore tecniche anti-debugging
    "PackerDetector",               # Rilevatore compressione/packing
    "VMDetector",                   # Rilevatore evasione macchine virtuali
    "EnhancedAntiDisasmDetector"    # Rilevatore anti-disassemblaggio potenziato
]

# Impostazioni dei file - Configurazioni per la gestione dei file binari
SUPPORTED_EXTENSIONS = [".exe", ".dll", ".bin", ".sys"]  # Estensioni supportate
MAX_FILE_SIZE = 100 * 1024 * 1024  # Dimensione massima file: 100MB

# Impostazioni di logging - Configurazione per i log di sistema
LOG_LEVEL = "INFO"  # Livello di log predefinito
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"  # Formato log

# Colori per output console - Codici ANSI per colorare l'output della console
COLORS = {
    "RED": "\033[91m",      # Rosso per errori
    "GREEN": "\033[92m",    # Verde per successi
    "YELLOW": "\033[93m",   # Giallo per avvisi
    "BLUE": "\033[94m",     # Blu per informazioni
    "PURPLE": "\033[95m",   # Viola per debug
    "CYAN": "\033[96m",     # Ciano per output speciali
    "WHITE": "\033[97m",    # Bianco per testo normale
    "END": "\033[0m",       # Reset colore
    "BOLD": "\033[1m"       # Grassetto
}

def get_version_info():
    """
    Restituisce informazioni formattate sulla versione del framework

    Returns:
        str: Stringa contenente nome, versione e descrizione dell'applicazione
    """
    return f"{APP_NAME} v{APP_VERSION} - {APP_DESCRIPTION}"

def get_project_info():
    """
    Restituisce un dizionario con tutte le informazioni del progetto

    Utile per esportare metadati del framework verso altri moduli o per
    generare report che includano informazioni sulla versione utilizzata.

    Returns:
        dict: Dizionario contenente tutte le informazioni principali del progetto
    """
    return {
        "name": APP_NAME,                      # Nome dell'applicazione
        "version": APP_VERSION,                # Versione corrente
        "description": APP_DESCRIPTION,        # Descrizione completa
        "author": APP_AUTHOR,                  # Autore del framework
        "root_path": str(PROJECT_ROOT),        # Percorso root del progetto
        "supported_extensions": SUPPORTED_EXTENSIONS,  # Estensioni file supportate
        "default_detectors": DEFAULT_DETECTORS         # Rilevatori predefiniti
    }
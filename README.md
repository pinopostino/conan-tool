# CONAN - Tool di Rilevamento Anti-Reversing

<div align="center">
  <img src="conanImmagine.png" alt="Detective Conan" width="200"/>

  **Progetto di Tesi Triennale in Informatica - Università di Bari**
</div>

Il progetto CONAN è un tool di rilevamento scritto in Python che implementa tecniche per identificare misure di anti-reversing nei file binari (PE Windows). Il progetto è strutturato come una tesi triennale in Informatica presso l'Università di Bari.

## 🏗️ Architettura del Sistema

Il tool è costruito su quattro componenti core che formano il motore di analisi. Il sistema è progettato con un'architettura modulare che separa la logica di rilevamento, la gestione dei dati e l'orchestrazione dell'analisi.

**DetectionResult**: rappresenta un singolo rilevamento. Contiene informazioni come il nome del detector, la tecnica rilevata, l'indirizzo di memoria, la descrizione, il livello di confidenza (0.0-1.0) e metadati aggiuntivi. Include un builder pattern per costruire risultati in modo fluido.

**AnalysisContext**: Modulo che gestisce tutti i dati del binario analizzato. Mantiene una cache intelligente per operazioni costose, raccoglie tutti i risultati delle detection, e fornisce metodi helper per accedere a sezioni, import/export e dati raw del file. Gestisce anche metadati come architettura, entry point e informazioni PE.

**BaseDetector**: Modulo con classe base astratta che definisce l'interfaccia comune per tutti i rilevatori. Fornisce metodi template per l'analisi, utilità per validazione indirizzi, calcolo della confidenza e logging unificato delle detection. Include anche il TaskMonitor per gestire progresso e cancellazione.

**DetectionEngine**: Orchestratore principale che coordina l'esecuzione di tutti i detector registrati. Gestisce il caricamento dei file binari, l'esecuzione sequenziale dei rilevatori con gestione robusta degli errori, e il monitoraggio del progresso in tempo reale. Supporta anche analisi selettive con subset di detector.

## 🔍 Detector

Il Tool implementa tre detector specializzati, ognuno focalizzato su una categoria specifica di tecniche anti-reversing. Ogni detector opera in modo indipendente e contribuisce ai risultati finali dell'analisi.

### 🛡️ AntiDebugDetector

Rileva molte tecniche anti-debugging attraverso diverse strategie:

- API sospette: IsDebuggerPresent, NtQueryInformationProcess
- Pattern binari per accesso al PEB (Process Environment Block)
- Timing attacks: RDTSC, GetTickCount
- Rilevamento hardware breakpoints tramite registri di debug (DR0–DR7)
- Manipolazione SEH (Structured Exception Handling)
- Detection di processi debugger attivi
- Detection di chiavi di registro specifiche

### 📦 PackerDetector

Specializzato nel rilevamento di compressione e offuscamento dei binari:

- Signature detection per famiglie di packer: UPX, VMProtect, Themida, ASPack
- Analisi entropia Shannon delle sezioni (soglia > 7.5 → cifrato/compresso)
- Rilevamento sezioni con nomi sospetti
- Sezioni con permessi anomali RWX
- Analisi import table minimali (tipiche dei loader)
- Detection di overlay data
- Anomalie dimensionali nei file

### 🖥️ VMDetector

Identifica tecniche di evasione da macchine virtuali:

- Indicatori VMware, VirtualBox, Hyper-V, QEMU (file, processi, chiavi di registro)
- API di hardware fingerprinting
- Query WMI sospette per info di sistema
- Prefix MAC address tipici delle VM
- Pattern di rilevamento CPU
- Signature di hypervisor

## 🖼️ GUI

L'interfaccia grafica è implementata con PyQt6. Include l'immagine di Detective Conan come rappresentazione del tool e citazione al famosissimo anime giapponese, supporto drag & drop per caricare file binari, selezione dei detector da eseguire tramite checkbox, barra di progresso durante l'analisi, e visualizzazione dei risultati attraverso tre tab: tabella dettagliata dei rilevamenti, report completo con analisi del rischio e raccomandazioni, e informazioni tecniche del binario. Supporta anche temi light/dark e export dei report.

## 🔧 Utils

Il modulo utils contiene il binary_parser.py, un parser binario che gestisce multiple architetture. Supporta il rilevamento automatico del formato (PE, ELF, Mach-O) tramite magic bytes, utilizza la libreria pefile per parsing completo dei file PE Windows con fallback a parser manuale, calcola hash di sicurezza (MD5, SHA1, SHA256) per identificazione, estrae metadati completi come architettura, entry point, sezioni con permessi e entropia, e parser di import/export table. Include anche funzioni helper per caricare i dati nel contesto di analisi.

## 🧪 SAMPLES

La directory samples contiene codice sorgente organizzato per categoria, generato con l'ausilio di LLM, principalmente il modello gratuito Deepseek V3.1, per testare le capacità di detection del Tool. Include antidebug_samples con test per API calls, manipolazione PEB, timing attacks e SEH, packed_samples con esempi di alta entropia, import minimali e signature di packer, e vm_samples con artifact di rilevamento VM. La cartella samples_compiled contiene le versioni compilate (.exe) pronte per il testing, permettendo di validare l'efficacia dei detector su casi noti.

## 🚀 Guida di Installazione

### Prerequisiti

- Python 3.8+ (testato con Python 3.9-3.12)
- Sistema Operativo: Windows 10/11 (raccomandato), Linux, macOS

### 1. Download del Progetto

```bash
git clone https://github.com/pinopostino/conan-tool.git
cd conan-tool
```

### 2. Installazione Dipendenze

```bash
# Installazione automatica delle dipendenze
pip install -r requirements.txt
```

Le dipendenze principali sono:

- PyQt6>=6.4.0 (interfaccia grafica)
- pefile>=2023.2.7 (parsing file PE)

### 3. Verifica Installazione

```bash
# Test del sistema
python conan_launcher.py --check
```

### 4. Esecuzione

**Modalità GUI (Raccomandato):**
```bash
python conan_launcher.py
```

**Modalità Command Line:**
```bash
python main.py percorso/del/file.exe
```

**Windows - Doppio Click:**
Esegui CONAN.bat

### 5. Primo Utilizzo

1. Avvia l'applicazione con `python conan_launcher.py`
2. Trascina un file binario (.exe, .dll) nell'area centrale o usa "Sfoglia"
3. Seleziona i detector desiderati (tutti attivi di default)
4. Clicca "🚀 Avvia Analisi CONAN"
5. Visualizza i risultati nelle tab "Rilevamenti", "Report" e "Informazioni sul file"

## ⚠️ Troubleshooting

**Errore PyQt6:**
```bash
pip uninstall PyQt6
pip install PyQt6 --no-cache-dir
```

**Errore pefile:**
```bash
pip install pefile --upgrade
```

**Python non riconosciuto:**

- Verifica che Python sia nel PATH di sistema
- Su Windows, reinstalla Python con "Add to PATH" selezionato

**GUI non si avvia:**
```bash
# Modalità debug
python main.py samples_compiled/test_sample.exe
```

**Preferibile avviare il file .bat in automatico**
Mediante il file .bat, si avvierà l'applicazione in modo automatico

La configurazione è ora completa e CONAN è pronto per l'analisi di file binari!
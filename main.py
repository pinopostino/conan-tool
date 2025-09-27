#!/usr/bin/env python3
"""
CONAN - Framework di Rilevamento Anti-Reversing
Punto di ingresso principale per l'esecuzione standalone del tool

Questo script permette di utilizzare CONAN dalla riga di comando senza la GUI.
Carica tutti i rilevatori disponibili e analizza il file binario specificato
come argomento da riga di comando.

Utilizzo:
    python main.py <percorso_file_binario>

Esempio:
    python main.py samples/malware.exe
"""

import sys
import os
from pathlib import Path

# Aggiunge la directory corrente al path per permettere le importazioni
sys.path.insert(0, str(Path(__file__).parent))

from core.detection_engine import DetectionEngine
from detectors.anti_debug_detector import AntiDebugDetector
from detectors.packer_detector import PackerDetector
from detectors.vm_detector import VMDetector


def main():
    """
    Funzione principale del programma

    Inizializza il motore di rilevamento, carica tutti i detector disponibili
    e analizza il file binario specificato come argomento da riga di comando.
    """
    print("CONAN - Framework di Rilevamento Anti-Reversing")
    print("=" * 50)

    # Crea il motore di rilevamento principale
    engine = DetectionEngine()

    # Caricamento della suite di rilevamento basata su pattern
    print("\n[PATTERN-BASED] Caricamento Suite di Rilevamento Pattern:")

    # Registra tutti i rilevatori basati su pattern
    anti_debug_detector = AntiDebugDetector()          # Rilevatore anti-debugging
    packer_detector = PackerDetector()                 # Rilevatore compressori/packer
    vm_detector = VMDetector()                         # Rilevatore evasione VM

    # Registra i rilevatori nel motore di analisi
    engine.register_detector(anti_debug_detector)
    engine.register_detector(packer_detector)
    engine.register_detector(vm_detector)

    # Mostra informazioni sui rilevatori caricati
    print(f"  + {anti_debug_detector.get_name()}: {anti_debug_detector.get_description()}")
    print(f"  + {packer_detector.get_name()}: {packer_detector.get_description()}")
    print(f"  + {vm_detector.get_name()}: {vm_detector.get_description()}")

    print(f"\n[READY] Motore di Rilevamento: {engine.get_detector_count()} detector caricati")
    print("Pronto per l'analisi!")

    # Verifica se è stato fornito un file da analizzare come argomento
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]  # Ottiene il percorso del file da analizzare

        # Verifica che il file esista prima di procedere con l'analisi
        if os.path.exists(binary_path):
            print(f"\nAnalizzando: {binary_path}")

            # Definisce la funzione di callback per mostrare il progresso dell'analisi
            def progress_callback(message, progress):
                """Callback per visualizzare il progresso dell'analisi"""
                print(f"[{progress*100:6.1f}%] {message}")

            try:
                # Esegue l'analisi del file binario
                context = engine.analyze(binary_path, progress_callback)
                results = context.get_results()  # Ottiene i risultati dell'analisi

                print(f"\nAnalisi completata: {len(results)} rilevazioni")

                # Mostra i risultati dell'analisi (massimo 10 per evitare output troppo lungo)
                print(f"\n[RISULTATI] Risultati Rilevamento:")
                for result in results[:10]:  # Mostra i primi 10 risultati
                    print(f"  -> {result}")

                # Se ci sono più di 10 risultati, mostra il conteggio dei rimanenti
                if len(results) > 10:
                    print(f"  ... e altri {len(results) - 10} rilevamenti")

            except Exception as e:
                # Gestisce eventuali errori durante l'analisi
                print(f"Analisi fallita: {e}")
        else:
            print(f"File non trovato: {binary_path}")
    else:
        print("\nUtilizzo: python main.py <percorso_file_binario>")
        print("Esempio: python main.py samples/malware.exe")


if __name__ == "__main__":
    # Esegue la funzione principale solo se lo script viene eseguito direttamente
    main()
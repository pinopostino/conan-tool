"""
Motore di Rilevamento CONAN - Implementazione Python
Tradotto dal DetectionEngine.java originale

Questo modulo implementa il motore principale di rilevamento del framework CONAN.
Il DetectionEngine coordina l'esecuzione di tutti i rilevatori registrati e gestisce
il flusso dell'analisi dai file binari fino alla generazione dei risultati finali.

Caratteristiche principali:
- Gestione centralizzata di tutti i rilevatori
- Coordinamento del processo di analisi
- Monitoraggio del progresso in tempo reale
- Gestione robusta degli errori
- Supporto per analisi selettive
"""

from typing import List, Optional, Callable
import traceback
from .analysis_context import AnalysisContext
from .base_detector import BaseDetector, TaskMonitor


class DetectionEngine:
    """
    Orchestratore principale per l'analisi CONAN.

    Questa classe gestisce tutti i rilevatori registrati e coordina il processo
    di analisi. Funge da punto centrale di controllo per l'esecuzione sequenziale
    dei detector e la raccolta dei risultati.

    Responsabilità:
    - Registrazione e gestione dei rilevatori
    - Coordinamento dell'analisi binaria
    - Monitoraggio del progresso
    - Gestione degli errori durante l'analisi
    - Aggregazione dei risultati finali
    """

    def __init__(self):
        """
        Inizializza il motore di rilevamento.

        Crea una lista vuota per contenere tutti i rilevatori che verranno
        registrati successivamente tramite register_detector().
        """
        self._detectors: List[BaseDetector] = []  # Lista dei rilevatori registrati
    
    def register_detector(self, detector: BaseDetector) -> None:
        """
        Registra un rilevatore nel motore di analisi.

        Aggiunge un nuovo rilevatore alla lista dei detector attivi.
        Evita duplicati controllando se il rilevatore è già presente.

        Args:
            detector: Istanza del rilevatore da registrare
        """
        if detector not in self._detectors:  # Evita duplicati
            self._detectors.append(detector)
    
    def unregister_detector(self, detector: BaseDetector) -> bool:
        """
        Rimuove un rilevatore dal motore di analisi.

        Cerca e rimuove il rilevatore specificato dalla lista dei detector attivi.
        Gestisce il caso in cui il rilevatore non sia presente.

        Args:
            detector: Istanza del rilevatore da rimuovere

        Returns:
            True se il rilevatore è stato trovato e rimosso, False altrimenti
        """
        try:
            self._detectors.remove(detector)  # Rimuove il rilevatore
            return True  # Rimozione avvenuta con successo
        except ValueError:
            return False  # Rilevatore non trovato
    
    def clear_detectors(self) -> None:
        """
        Rimuove tutti i rilevatori registrati.

        Svuota completamente la lista dei detector, utile per reimpostare
        il motore o per configurazioni dinamiche.
        """
        self._detectors.clear()  # Svuota la lista dei rilevatori
    
    def analyze(self, binary_path: str,
                progress_callback: Optional[Callable[[str, float], None]] = None) -> AnalysisContext:
        """
        Esegue l'analisi completa di un file binario.

        Questa è la funzione principale del motore che coordina l'intero processo
        di analisi. Carica il file binario, esegue tutti i rilevatori registrati
        e raccoglie i risultati in un contesto di analisi unificato.

        Fasi dell'analisi:
        1. Caricamento e parsing del file binario
        2. Inizializzazione del contesto di analisi
        3. Esecuzione sequenziale di tutti i rilevatori
        4. Raccolta e aggregazione dei risultati
        5. Gestione degli errori e reporting finale

        Args:
            binary_path: Percorso del file binario da analizzare
            progress_callback: Callback opzionale per aggiornamenti di progresso (messaggio, percentuale)

        Returns:
            AnalysisContext contenente tutti i risultati dell'analisi

        Raises:
            Exception: Se l'analisi fallisce durante il caricamento del file
        """
        # Crea il contesto di analisi che conterrà tutti i risultati
        context = AnalysisContext(binary_path)
        monitor = TaskMonitor(progress_callback)  # Monitor per il progresso

        # Fase 1: Caricamento dei dati binari
        try:
            self._load_binary_data(context, monitor)
        except Exception as e:
            monitor.set_message(f"Caricamento binario fallito: {str(e)}")
            raise

        # Fase 2: Inizializzazione dell'analisi
        monitor.update_progress("Inizializzazione analisi CONAN...", 0.0)

        detector_count = len(self._detectors)
        if detector_count == 0:
            monitor.set_message("Nessun rilevatore registrato")
            return context

        # Fase 3: Esecuzione di tutti i rilevatori
        for i, detector in enumerate(self._detectors):
            # Controlla se l'analisi è stata cancellata dall'utente
            if monitor.is_cancelled():
                monitor.set_message("Analisi cancellata dall'utente")
                break

            # Calcola il progresso basato sul rilevatore corrente
            detector_progress = i / detector_count
            monitor.update_progress(f"Esecuzione {detector.get_name()}...", detector_progress)

            try:
                # Esegue il rilevatore corrente
                detector.analyze(context, monitor)

                # Aggiorna il progresso dopo il completamento del rilevatore
                completed_progress = (i + 1) / detector_count
                results_so_far = context.get_result_count()
                monitor.update_progress(
                    f"Completato {detector.get_name()} - {results_so_far} rilevazioni totali",
                    completed_progress
                )

            except Exception as e:
                # Gestione robusta degli errori - non interrompe l'analisi
                error_msg = f"Errore in {detector.get_name()}: {str(e)}"
                monitor.set_message(error_msg)

                # Log dell'errore per debugging ma continua con altri rilevatori
                print(f"Errore Motore CONAN: {error_msg}")
                print(f"Traceback: {traceback.format_exc()}")

                # Opzionalmente aggiunge l'errore come risultato per trasparenza
                if hasattr(detector, 'create_result'):
                    try:
                        error_result = (detector.create_result()
                                      .technique("Errore Rilevatore")
                                      .description(f"Rilevatore fallito: {str(e)}")
                                      .address(0)
                                      .confidence(0.0)
                                      .evidence(f"Eccezione: {e.__class__.__name__}")
                                      .metadata("error_type", e.__class__.__name__)
                                      .metadata("error_message", str(e))
                                      .build())
                        context.add_result(error_result)
                    except:
                        pass  # Non lasciare che la gestione errori stessa fallisca

        # Fase 4: Finalizzazione e reporting
        final_count = context.get_result_count()
        monitor.update_progress(f"Analisi completata: {final_count} rilevazioni trovate", 1.0)

        return context
    
    def _load_binary_data(self, context: AnalysisContext, monitor: TaskMonitor) -> None:
        """
        Load binary data into the analysis context
        This will be implemented with LIEF/pefile for actual binary parsing
        
        Args:
            context: Analysis context to populate
            monitor: Progress monitor
        """
        monitor.set_message("Loading binary file...")
        
        try:
            # Parse binary with full PE/ELF support
            from utils.binary_parser import parse_binary, load_binary_into_context
            
            monitor.set_message("Parsing binary structure...")
            binary_info = parse_binary(context.binary_path)
            
            monitor.set_message(f"Loaded {binary_info.file_type} binary ({binary_info.file_size} bytes)")
            
            # Load parsed information into context
            load_binary_into_context(context, binary_info)
            
            # Additional cache info
            context.cache_value("loaded_timestamp", __import__('time').time())
            
            # Log import info for debugging
            if binary_info.imports:
                monitor.set_message(f"Parsed {len(binary_info.imports)} imports successfully")
            else:
                monitor.set_message("Warning: No imports found in binary")
            
        except FileNotFoundError:
            raise Exception(f"Binary file not found: {context.binary_path}")
        except PermissionError:
            raise Exception(f"Permission denied reading: {context.binary_path}")
        except Exception as e:
            raise Exception(f"Failed to load binary: {str(e)}")
    
    def get_detectors(self) -> List[BaseDetector]:
        """Get list of registered detectors (returns copy)"""
        return self._detectors.copy()
    
    def get_detector_count(self) -> int:
        """Get number of registered detectors"""
        return len(self._detectors)
    
    def get_detector_by_name(self, name: str) -> Optional[BaseDetector]:
        """Get detector by name"""
        for detector in self._detectors:
            if detector.get_name() == name:
                return detector
        return None
    
    def has_detector(self, name: str) -> bool:
        """Check if detector with given name is registered"""
        return self.get_detector_by_name(name) is not None
    
    def get_detector_names(self) -> List[str]:
        """Get list of registered detector names"""
        return [detector.get_name() for detector in self._detectors]
    
    def analyze_with_selected_detectors(self, binary_path: str, 
                                      detector_names: List[str],
                                      progress_callback: Optional[Callable[[str, float], None]] = None) -> AnalysisContext:
        """
        Analyze with only selected detectors
        
        Args:
            binary_path: Path to binary file
            detector_names: List of detector names to run
            progress_callback: Optional progress callback
            
        Returns:
            AnalysisContext with results
        """
        # Temporarily save current detectors
        original_detectors = self._detectors.copy()
        
        try:
            # Filter to only selected detectors
            selected_detectors = [d for d in self._detectors if d.get_name() in detector_names]
            self._detectors = selected_detectors
            
            # Run analysis
            return self.analyze(binary_path, progress_callback)
            
        finally:
            # Restore original detectors
            self._detectors = original_detectors
    
    def __str__(self) -> str:
        return f"DetectionEngine({len(self._detectors)} detectors)"
    
    def __repr__(self) -> str:
        detector_names = [d.get_name() for d in self._detectors]
        return f"DetectionEngine(detectors={detector_names})"


# Example usage and testing
if __name__ == "__main__":
    from .base_detector import TestDetector
    
    # Create engine and register test detector
    engine = DetectionEngine()
    engine.register_detector(TestDetector())
    
    print(f"Engine: {engine}")
    print(f"Detectors: {engine.get_detector_names()}")
    
    # Test progress callback
    def progress_callback(message: str, progress: float):
        print(f"Progress: {progress*100:.1f}% - {message}")
    
    # This would fail because test.exe doesn't exist, but shows the structure
    try:
        context = engine.analyze("test.exe", progress_callback)
        print(f"Analysis complete: {context.get_result_count()} results")
    except Exception as e:
        print(f"Expected error: {e}")
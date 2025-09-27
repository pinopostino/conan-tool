"""
CONAN Main Window - PyQt6 GUI
Modern interface for the CONAN Anti-Reversing Detection Framework
"""

import sys
import os
from pathlib import Path
from typing import Optional, List
import threading
import traceback
import logging
logging.basicConfig(level=logging.DEBUG)

from unittest import result

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
    QTabWidget, QProgressBar, QFileDialog, QMessageBox, QFrame,
    QGroupBox, QCheckBox, QSplitter, QHeaderView, QAbstractItemView,
    QStatusBar, QMenuBar, QToolBar, QComboBox
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QPropertyAnimation, 
    QEasingCurve, QRect
)
from PyQt6.QtGui import (
    QFont, QPixmap, QPalette, QColor, QIcon, QAction, QDragEnterEvent, 
    QDropEvent, QTextCursor
)

# Import CONAN framework
sys.path.append(str(Path(__file__).parent.parent))
from core.detection_engine import DetectionEngine
from core.detection_result import DetectionResult

# Import standard detectors
from detectors.anti_debug_detector import AntiDebugDetector
from detectors.packer_detector import PackerDetector
from detectors.vm_detector import VMDetector





class AnalysisWorker(QThread):
    """Worker thread for running CONAN analysis"""
    
    progress_updated = pyqtSignal(str, float)  # message, progress
    analysis_complete = pyqtSignal(list)  # [results, stats] where stats can be None
    analysis_error = pyqtSignal(str)  # error message
    
    def __init__(self, binary_path: str, detectors: List[str]):
        super().__init__()
        self.binary_path = binary_path
        self.selected_detectors = detectors
        self.cancelled = False
    def run(self):
        """Run analysis in background thread"""
        try:
            # Create engine with standard detector selection
            engine = DetectionEngine()
            
            # Registrazione dei detector standard
            if "AntiDebugDetector" in self.selected_detectors:
                engine.register_detector(AntiDebugDetector())
            if "PackerDetector" in self.selected_detectors:
                engine.register_detector(PackerDetector())
            if "VMDetector" in self.selected_detectors:
                engine.register_detector(VMDetector())

            
            # Run analysis with progress callback
            def progress_callback(message: str, progress: float):
                if not self.cancelled:
                    self.progress_updated.emit(message, progress)
            
            context = engine.analyze(self.binary_path, progress_callback)
            
            if not self.cancelled:
                results = context.get_results()
                # Nessuna Hybrid/Capstone: emetti solo i risultati
                self.analysis_complete.emit([results, None])
                
        except Exception as e:
            if not self.cancelled:
                self.analysis_error.emit(str(e))

    def cancel(self):
        """Cancel the analysis"""
        self.cancelled = True


class ConanMainWindow(QMainWindow):
    """Main window for CONAN GUI"""
    
    def __init__(self):
        super().__init__()
        self.current_binary_path: Optional[str] = None
        self.analysis_worker: Optional[AnalysisWorker] = None
        self.current_results: List[DetectionResult] = []
        
        # Theme state
        self.is_dark_mode = False
        
        # Set application icon
        self.setup_app_icon()
        
        self.setup_ui()
        self.setup_menu_bar()
        self.setup_status_bar()
        self.setup_drag_drop()
        self.apply_theme()
        
        # Start with welcome message
        self.show_welcome_message()
    
    def setup_app_icon(self):
        """Set up application icon"""
        try:
            import os
            
            # Load the PNG icon
            icon_path = os.path.join(os.path.dirname(__file__), "..", "conanImmagine.png")
            if os.path.exists(icon_path):
                # Set window icon
                icon = QIcon(icon_path)
                self.setWindowIcon(icon)
                
                # Set application icon globally
                QApplication.instance().setWindowIcon(icon)
        except Exception as e:
            print(f"Warning: Could not set application icon: {e}")
    
    def setup_ui(self):
        """Setup the modern user interface with sidebar layout"""
        self.setWindowTitle("CONAN - Framework di Rilevamento Anti-Reversing")
        self.setGeometry(100, 100, 1600, 1000)
        self.setMinimumSize(1200, 800)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main horizontal layout (sidebar + content)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create sidebar
        self.create_sidebar(main_layout)
        
        # Create main content area
        self.create_main_content(main_layout)
    
    def create_sidebar(self, parent_layout):
        """Create modern sidebar with controls and Detective Conan image"""
        # Sidebar widget
        sidebar_widget = QWidget()
        sidebar_widget.setObjectName("sidebar")
        sidebar_widget.setFixedWidth(380)
        
        sidebar_layout = QVBoxLayout(sidebar_widget)
        sidebar_layout.setContentsMargins(20, 20, 20, 20)
        sidebar_layout.setSpacing(15)
        
        # CONAN Logo and Image Section
        self.create_logo_section(sidebar_layout)
        
        # File Selection Section
        self.create_file_section(sidebar_layout)
        
        # Configuration Section
        self.create_config_section(sidebar_layout)
        
        # Analysis Control Section
        self.create_control_section(sidebar_layout)
        
        # Progress Section
        self.create_progress_section(sidebar_layout)
        
        # Spacer to push everything to top
        sidebar_layout.addStretch()
        
        # Add sidebar to main layout
        parent_layout.addWidget(sidebar_widget)
    
    def create_logo_section(self, parent_layout):
        """Create logo section with Detective Conan image"""
        logo_frame = QFrame()
        logo_frame.setObjectName("logoFrame")
        logo_frame.setFixedHeight(260)  # Ridotto per dare più spazio ai controlli sotto
        
        logo_layout = QVBoxLayout(logo_frame)
        logo_layout.setContentsMargins(10, 10, 10, 10)  # Margini uniformi
        logo_layout.setSpacing(0)
        logo_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)  # Usa Qt già importato all'inizio
        
        # Load Detective Conan PNG image
        try:
            import os
            
            # Load the PNG image with absolute path
            png_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "conanImmagine.png"))
            
            if os.path.exists(png_path):
                # Create QLabel for PNG image
                image_label = QLabel()
                image_label.setObjectName("logoImage")
                image_label.setFixedSize(220, 220)  # Ridotto per farlo entrare meglio
                
                # Load and validate pixmap
                pixmap = QPixmap(png_path)
                if not pixmap.isNull():
                    # Scale image to fit label
                    scaled_pixmap = pixmap.scaled(
                        220, 220, 
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation
                    )
                    image_label.setPixmap(scaled_pixmap)
                    image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                    image_label.setScaledContents(False)  # Non scalare automaticamente
                    
                    logo_layout.addWidget(image_label, 0, Qt.AlignmentFlag.AlignCenter)
                else:
                    print(f"Warning: Could not load image from {png_path}")
                    self.create_text_logo(logo_layout)
            else:
                print(f"Warning: Image file not found at {png_path}")
                self.create_text_logo(logo_layout)
        except Exception as e:
            print(f"Warning: Error loading image: {e}")
            self.create_text_logo(logo_layout)
        
        parent_layout.addWidget(logo_frame)
    
    def create_text_logo(self, parent_layout):
        """Create text-based logo fallback"""
        logo_text = QLabel("🕵️‍♂️")
        logo_text.setObjectName("logoIcon")
        logo_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_text.setStyleSheet("font-size: 48px;")
        parent_layout.addWidget(logo_text, 0, Qt.AlignmentFlag.AlignCenter)
        
        # Add title for fallback
        title_label = QLabel("CONAN")
        title_label.setObjectName("logoTitle")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        parent_layout.addWidget(title_label)
        
        subtitle_label = QLabel("Anti-Reversing Detection")
        subtitle_label.setObjectName("logoSubtitle") 
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        parent_layout.addWidget(subtitle_label)
    
    def create_main_content(self, parent_layout):
        """Create main content area"""
        # Content widget
        content_widget = QWidget()
        content_widget.setObjectName("contentArea")
        
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(15)
        
        # Modern header with stats
        self.create_modern_header(content_layout)
        
        # Results section (takes most space)
        self.create_results_section(content_layout)
        
        parent_layout.addWidget(content_widget)
    
    def create_modern_header(self, parent_layout):
        """Create modern header with stats and info"""
        header_frame = QFrame()
        header_frame.setObjectName("modernHeader")
        
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(20, 15, 20, 15)
        header_layout.setSpacing(20)
        
        # Current file info
        file_info_layout = QVBoxLayout()
        
        self.current_file_label = QLabel("Nessun File Selezionato")
        self.current_file_label.setObjectName("currentFileLabel")
        file_info_layout.addWidget(self.current_file_label)
        
        self.file_details_label = QLabel("Selezion a un file per iniziare l'analisi")
        self.file_details_label.setObjectName("fileDetailsLabel")
        file_info_layout.addWidget(self.file_details_label)
        
        header_layout.addLayout(file_info_layout)
        
        # Stats section
        stats_layout = QVBoxLayout()
        
        self.stats_label = QLabel("Pronto")
        self.stats_label.setObjectName("statsLabel")
        self.stats_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        stats_layout.addWidget(self.stats_label)
        
        self.detection_count_label = QLabel("0 detections")
        self.detection_count_label.setObjectName("detectionCountLabel") 
        self.detection_count_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        stats_layout.addWidget(self.detection_count_label)
        
        header_layout.addLayout(stats_layout)
        
        parent_layout.addWidget(header_frame)
    
    def create_control_section(self, parent_layout):
        """Create analysis control section"""
        control_frame = QGroupBox("Controlli Analisi")
        control_frame.setObjectName("controlFrame")
        
        control_layout = QVBoxLayout(control_frame)
        control_layout.setSpacing(10)
        
        # Main analyze button
        self.analyze_button = QPushButton("🚀 Avvia Analisi CONAN")
        self.analyze_button.setObjectName("analyzeButton")
        self.analyze_button.clicked.connect(self.run_analysis)
        self.analyze_button.setEnabled(False)
        self.analyze_button.setMinimumHeight(45)
        
        # Cancel button
        self.cancel_button = QPushButton("❌ Annulla Analisi")
        self.cancel_button.setObjectName("cancelButton")
        self.cancel_button.clicked.connect(self.cancel_analysis)
        self.cancel_button.setVisible(False)
        self.cancel_button.setMinimumHeight(35)
        
        # Theme toggle button
        self.dark_mode_button = QPushButton("🌙 Modalità Scura")
        self.dark_mode_button.setObjectName("darkModeButton")
        self.dark_mode_button.clicked.connect(self.toggle_dark_mode)
        self.dark_mode_button.setMinimumHeight(35)
        self.dark_mode_button.setToolTip("Cambia tra tema chiaro e scuro")
        
        control_layout.addWidget(self.analyze_button)
        control_layout.addWidget(self.cancel_button)
        control_layout.addWidget(self.dark_mode_button)
        
        parent_layout.addWidget(control_frame)
        
    
    def create_file_section(self, parent_layout):
        """Create file selection section"""
        file_group = QGroupBox("")
        file_layout = QHBoxLayout(file_group)
        
        self.file_path_label = QLabel("Trascina un file binario qui o clicca Sfoglia...")
        self.file_path_label.setObjectName("filePathLabel")
        self.file_path_label.setStyleSheet("padding: 15px; border: 2px dashed #ccc; border-radius: 8px;")
        
        self.browse_button = QPushButton("Sfoglia...")
        self.browse_button.setObjectName("browseButton")
        self.browse_button.clicked.connect(self.browse_file)
        
        file_layout.addWidget(self.file_path_label, 1)
        file_layout.addWidget(self.browse_button)
        
        parent_layout.addWidget(file_group)
    
    def create_config_section(self, parent_layout):
        """Create configuration section"""
        config_group = QGroupBox("Configurazione Analisi")
        config_layout = QVBoxLayout(config_group)
        config_layout.setSpacing(8)
        
        # Title
        title_label = QLabel("Seleziona Rilevatori:")
        title_label.setObjectName("configTitle")
        config_layout.addWidget(title_label)
        
        # Detector standard
        self.antidebug_check = QCheckBox("🛡️ Rilevamento Anti-Debug")
        self.antidebug_check.setChecked(True)
        self.antidebug_check.setObjectName("detectorCheck")
        self.antidebug_check.setToolTip("Rileva tecniche anti-debugging")

 
        
        self.packer_check = QCheckBox("📦 Rilevamento Compressori")
        self.packer_check.setChecked(True)
        self.packer_check.setObjectName("detectorCheck")
        self.packer_check.setToolTip("Rileva eseguibili compressi/impacchettati (67 metodi)")
        
        self.vm_check = QCheckBox("🖥️ Rilevamento Evasione VM")
        self.vm_check.setChecked(True)
        self.vm_check.setObjectName("detectorCheck")
        self.vm_check.setToolTip("Rileva evasione macchine virtuali (60+ metodi)")
        
        # Aggiungi i detector al layout
        config_layout.addWidget(self.antidebug_check)
        config_layout.addWidget(self.packer_check)
        config_layout.addWidget(self.vm_check)
        
        # Aggiungi il gruppo al layout principale
        parent_layout.addWidget(config_group)

       
    
    def create_progress_section(self, parent_layout):
        """Create progress section"""
        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("progressBar")
        self.progress_bar.setVisible(False)
        self.progress_bar.setTextVisible(True)
        
        parent_layout.addWidget(self.progress_bar)
    
    def create_results_section(self, parent_layout):
        """Create results section with tabs"""
        self.results_tabs = QTabWidget()
        self.results_tabs.setObjectName("resultsTabs")
        
        # Results table tab
        self.create_results_table_tab()
        
        # Summary report tab
        self.create_summary_tab()
        
        # Binary info tab
        self.create_binary_info_tab()
        
        parent_layout.addWidget(self.results_tabs, 1)  # Expand to fill space
    
    def create_results_table_tab(self):
        """Create results table tab"""
        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setObjectName("resultsTable")
        
        # Setup table columns
        columns = ["Detector", "Technique", "Address", "Description", "Evidence"]
        self.results_table.setColumnCount(len(columns))
        self.results_table.setHorizontalHeaderLabels(columns)
        
        # Table configuration
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSortingEnabled(True)
        
        # Resize columns
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        
        # Double-click handler
        self.results_table.itemDoubleClicked.connect(self.on_result_double_click)
        
        table_layout.addWidget(self.results_table)
        
        self.results_tabs.addTab(table_widget, "Rilevamenti")
    
    def create_summary_tab(self):
        """Create summary report tab"""
        self.summary_text = QTextEdit()
        self.summary_text.setObjectName("summaryText")
        self.summary_text.setReadOnly(True)
        self.summary_text.setFont(QFont("Consolas", 10))
        
        self.results_tabs.addTab(self.summary_text, "Report")
    
    def create_binary_info_tab(self):
        """Create binary info tab"""
        self.binary_info_text = QTextEdit()
        self.binary_info_text.setObjectName("binaryInfoText")
        self.binary_info_text.setReadOnly(True)
        self.binary_info_text.setFont(QFont("Consolas", 10))
        
        self.results_tabs.addTab(self.binary_info_text, "Informazioni sul file")
    
    def setup_menu_bar(self):
        """Setup menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        open_action = QAction("Apri file...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.browse_file)
        file_menu.addAction(open_action)
        
        file_menu.addSeparator()
        
        export_action = QAction("Esporta Report...", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self.export_report)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Esci", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Analysis menu
        analysis_menu = menubar.addMenu("Analysis")
        
        run_action = QAction("Avvia Analisi", self)
        run_action.setShortcut("F5")
        run_action.triggered.connect(self.run_analysis)
        analysis_menu.addAction(run_action)
        
        cancel_action = QAction("Cancella Analisi", self)
        cancel_action.setShortcut("Esc")
        cancel_action.triggered.connect(self.cancel_analysis)
        analysis_menu.addAction(cancel_action)
        
        # View menu  
        view_menu = menubar.addMenu("Visualizza")
        
        self.dark_mode_action = QAction("Dark Mode", self)
        self.dark_mode_action.setCheckable(True)
        self.dark_mode_action.setChecked(False)
        self.dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(self.dark_mode_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About CONAN", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready - Load a binary file to begin analysis")
    
    def setup_drag_drop(self):
        """Setup drag and drop functionality"""
        self.setAcceptDrops(True)
    
    def toggle_dark_mode(self):
        """Toggle between light and dark mode"""
        self.is_dark_mode = not self.is_dark_mode
        if self.is_dark_mode:
            self.dark_mode_action.setText("Light Mode")
            self.dark_mode_button.setText("☀️ Light Mode")
            self.dark_mode_button.setToolTip("Switch to light theme")
        else:
            self.dark_mode_action.setText("Dark Mode")
            self.dark_mode_button.setText("🌙 Dark Mode")
            self.dark_mode_button.setToolTip("Switch to dark theme")
        self.apply_theme()
    
    def apply_theme(self):
        """Apply current theme (light or dark)"""
        if self.is_dark_mode:
            self.apply_dark_theme()
        else:
            self.apply_light_theme()
    
    def apply_light_theme(self):
        """Apply light theme styling"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f8f9fa;
                color: #212529;
            }
            
            #sidebar {
                background-color: #f8f9fa;
                border-right: 1px solid #e9ecef;
            }
            
            #logoFrame {
                background-color: #ffffff;  /* o #2d2d2d per dark */
                border: 1px solid #e9ecef;  /* o #404040 per dark */
                border-radius: 12px;
                padding: 10px;  /* Padding uniforme */
                margin-bottom: 10px;
            }
            
            #logoTitle {
                font-size: 24px;
                font-weight: bold;
                color: #1e40af;
                margin: 0px;
            }
            
            #logoSubtitle {
                font-size: 12px;
                color: #6b7280;
                margin: 0px;
            }
            
            #logoVersion {
                font-size: 10px;
                color: #9ca3af;
                margin: 0px;
            }
            
            #modernHeader {
                background-color: #ffffff;
                border: 1px solid #e9ecef;
                border-radius: 8px;
                margin-bottom: 15px;
            }
            
            #currentFileLabel {
                font-size: 16px;
                font-weight: bold;
                color: #1f2937;
            }
            
            #fileDetailsLabel {
                font-size: 12px;
                color: #6b7280;
            }
            
            #statsLabel {
                font-size: 14px;
                font-weight: bold;
                color: #059669;
            }
            
            #detectionCountLabel {
                font-size: 12px;
                color: #6b7280;
            }
            
            #contentArea {
                background-color: #ffffff;
            }
            
            #titleLabel {
                color: #495057;
                font-weight: bold;
            }
            
            #subtitleLabel {
                color: #6c757d;
                font-style: italic;
            }
            
            #statsLabel {
                color: #28a745;
                font-weight: bold;
            }
            
            #filePathLabel {
                background-color: #f8f9fa;
                color: #6c757d;
                font-size: 12px;
            }
            
            #browseButton {
                background-color: #007bff;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            
            #browseButton:hover {
                background-color: #0056b3;
            }
            
            #analyzeButton {
                background-color: #28a745;
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 14px;
            }
            
            #analyzeButton:hover {
                background-color: #218838;
            }
            
            #analyzeButton:disabled {
                background-color: #6c757d;
            }
            
            #cancelButton {
                background-color: #dc3545;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
            }
            
            #cancelButton:hover {
                background-color: #c82333;
            }
            
            #darkModeButton {
                background-color: #6c757d;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            
            #darkModeButton:hover {
                background-color: #5a6268;
            }
            
            #progressBar {
                border: 1px solid #dee2e6;
                border-radius: 6px;
                text-align: center;
            }
            
            #progressBar::chunk {
                background-color: #007bff;
                border-radius: 5px;
            }
            
                        QGroupBox {
                font-weight: bold;
                font-size: 13px;  /* Era 14px, prova 13px */
                /* resto uguale */
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px 0 8px;
                color: #495057;
            }
            
            QTabWidget::pane {
                border: 1px solid #dee2e6;
                border-radius: 8px;
                background-color: white;
            }
            
            QTabBar::tab {
                background-color: #e9ecef;
                color: #495057;
                padding: 8px 16px;
                margin: 2px;
                border-radius: 6px 6px 0 0;
            }
            
            QTabBar::tab:selected {
                background-color: #007bff;
                color: white;
            }
            
            #resultsTable {
                gridline-color: #dee2e6;
                background-color: white;
                alternate-background-color: #f8f9fa;
            }
            
            #resultsTable::item {
                padding: 8px;
            }
            
            #summaryText, #binaryInfoText {
                background-color: #ffffff;
                color: #212529;
                border: 1px solid #dee2e6;
                border-radius: 6px;
                padding: 10px;
                font-family: 'Consolas', 'Monaco', monospace;
                selection-background-color: #007bff;
                selection-color: white;
            }
            
            #configTitle {
                font-size: 13px;
                font-weight: bold;
                color: #495057;
                margin-bottom: 5px;
            }
            
            #detectorCheck {
                font-size: 12px;
                font-weight: normal;
                color: #495057;
                padding: 4px 0px;
                margin: 2px 0px;
            }
            
            QCheckBox {
                font-weight: normal;
                color: #495057;
            }
            
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                margin-right: 8px;
            }
            
            QCheckBox::indicator:unchecked {
                border: 2px solid #6c757d;
                border-radius: 4px;
                background-color: white;
            }
            
            QCheckBox::indicator:checked {
                border: 2px solid #007bff;
                border-radius: 4px;
                background-color: #007bff;
            }
            
            QCheckBox::indicator:disabled {
                border: 2px solid #dee2e6;
                background-color: #f8f9fa;
            }
        """)
    
    def show_welcome_message(self):
        """Show welcome message in summary tab"""
        welcome_text = """
CONAN - Tool di Rilevamento Anti-Reversing
==========================================
Benvenuto in CONAN 🕵️‍♂️
Il tool modulare per rilevare le tecniche di anti-reversing usate dai binari per sfuggire all’analisi.

🚀 FUNZIONALITÀ
-Anti-Debug
Rileva tecniche che un programma usa per impedire o interferire con il debug (es. lettura del PEB, controlli di timing, breakpoint hardware/software). Segnala chiamate API sospette, pattern comportamentali e prove di contromisure che rendono difficile l’analisi dinamica.

-Packer
Individua quando un binario è stato “impacchettato” o offuscato (compattatori come UPX/VMProtect/Themida, sezioni con alta entropia, import ridotte). Fornisce indizi sul tipo di packer e sull’eventuale presenza di decompressione o loader runtime, utile a decidere se fare unpacking prima di analisi approfondite.

-VM-Evasion
Cerca tecniche usate per riconoscere ed evitare macchine virtuali e ambienti di sandbox (es. controlli su hardware fingerprint, query WMI, risposte tipiche di VMware/VirtualBox/Hyper-V). Segnala tentativi di fingerprinting o comportamenti condizionali che indicano che il campione si comporta differentemente in ambienti virtualizzati.

-GUI 
drag & drop, progress bar, report dettagliati ed export.

🛠️ COME USARLO

1.Trascina un binario o clicca Browse.

2.Seleziona i detector (consigliato: tutti).

3.Premi Run CONAN Analysis.

        """
        self.summary_text.setPlainText(welcome_text)
        self.binary_info_text.setPlainText("Carica il binario per avere più informazioni...")
    
    def browse_file(self):
        """Browse for binary file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary File",
            "",
            "Executable Files (*.exe *.dll *.sys);;All Files (*)"
        )
        
        if file_path:
            self.load_binary_file(file_path)
    
    def load_binary_file(self, file_path: str):
        """Load binary file"""
        try:
            if not os.path.exists(file_path):
                QMessageBox.warning(self, "Error", f"File not found: {file_path}")
                return
            
            self.current_binary_path = file_path
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            # Update UI
            self.file_path_label.setText(f"{file_name} ({file_size:,} bytes)")
            self.file_path_label.setStyleSheet("padding: 15px; border: 2px solid #28a745; border-radius: 8px; background-color: #d4edda;")
            
            self.analyze_button.setEnabled(True)
            self.status_bar.showMessage(f"Loaded: {file_name}")
            
            # Update stats
            # Update header info  
            self.current_file_label.setText(file_name)
            self.file_details_label.setText(f"{file_size:,} bytes | Ready for analysis")
            self.stats_label.setText("File loaded")
            self.detection_count_label.setText("0 detections")
            
            # Show basic binary info
            self.show_binary_info()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load file: {str(e)}")
    
    def show_binary_info(self):
        """Show basic binary information"""
        if not self.current_binary_path:
            return
        
        try:
            from utils.binary_parser import parse_binary
            
            binary_info = parse_binary(self.current_binary_path)
            
            info_text = f"""
BINARY INFORMATION
==================

File Path: {binary_info.file_path}
File Size: {binary_info.file_size:,} bytes
File Type: {binary_info.file_type}
Architecture: {binary_info.architecture}
Entry Point: 0x{binary_info.entry_point:08x}

HASHES:
MD5:    {binary_info.md5}
SHA1:   {binary_info.sha1}
SHA256: {binary_info.sha256}

SECTIONS: {len(binary_info.sections)}
"""
            
            for section in binary_info.sections:
                perms = ""
                if section.get('readable'): perms += "R"
                if section.get('writable'): perms += "W"  
                if section.get('executable'): perms += "X"
                
                info_text += f"  {section['name']:<10} 0x{section['virtual_address']:08x} {section['virtual_size']:8,} bytes [{perms}]\n"
            
            info_text += f"\nIMPORTS: {len(binary_info.imports)}\n"
            
            # Group imports by library
            imports_by_lib = {}
            for imp in binary_info.imports:
                lib = imp.get('library', 'unknown')
                if lib not in imports_by_lib:
                    imports_by_lib[lib] = []
                imports_by_lib[lib].append(imp['name'])
            
            for lib, funcs in list(imports_by_lib.items())[:10]:  # Show first 10 libraries
                info_text += f"  {lib}: {len(funcs)} functions\n"
                for func in funcs[:5]:  # Show first 5 functions per library
                    info_text += f"    - {func}\n"
                if len(funcs) > 5:
                    info_text += f"    ... and {len(funcs) - 5} more\n"
            
            if len(imports_by_lib) > 10:
                info_text += f"  ... and {len(imports_by_lib) - 10} more libraries\n"
            
            if binary_info.exports:
                info_text += f"\nEXPORTS: {len(binary_info.exports)}\n"
                for exp in binary_info.exports[:10]:
                    info_text += f"  {exp['name']} @ 0x{exp.get('address', 0):08x}\n"
                if len(binary_info.exports) > 10:
                    info_text += f"  ... and {len(binary_info.exports) - 10} more\n"
            
            self.binary_info_text.setPlainText(info_text)
            
        except Exception as e:
            self.binary_info_text.setPlainText(f"Error parsing binary: {str(e)}")
    
    def run_analysis(self):
        """Run CONAN analysis"""
        if not self.current_binary_path:
            QMessageBox.warning(self, "Warning", "Please select a binary file first.")
            return
        
        # Get selected detectors con supporto architettura ibrida
        selected_detectors = []
        
        # Detector standard selezionati
        if self.packer_check.isChecked():
            selected_detectors.append("PackerDetector")
        if self.vm_check.isChecked():
            selected_detectors.append("VMDetector")
        if self.antidebug_check.isChecked():
            selected_detectors.append("AntiDebugDetector")


        else:
            # MODALITÀ STANDARD: Detector pattern-based originali
            if self.antidebug_check and self.antidebug_check.isChecked():
                selected_detectors.append("AntiDebugDetector")
            if self.packer_check.isChecked():
                selected_detectors.append("PackerDetector")
            if self.vm_check.isChecked():
                selected_detectors.append("VMDetector")
 
        
        if not selected_detectors:
            QMessageBox.warning(self, "Attenzione", "Seleziona almeno un detector.")
            return
        
        # Setup UI for analysis
        self.analyze_button.setVisible(False)
        self.cancel_button.setVisible(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.current_results.clear()
        
        # Start analysis worker
        self.analysis_worker = AnalysisWorker(self.current_binary_path, selected_detectors)
        self.analysis_worker.progress_updated.connect(self.on_progress_updated)
        self.analysis_worker.analysis_complete.connect(self.on_analysis_complete)
        self.analysis_worker.analysis_error.connect(self.on_analysis_error)
        self.analysis_worker.start()
        
        self.status_bar.showMessage("Avviando CONAN analysis...")
    
    def cancel_analysis(self):
        """Cancel running analysis"""
        if self.analysis_worker and self.analysis_worker.isRunning():
            self.analysis_worker.cancel()
            self.analysis_worker.wait(3000)  # Wait up to 3 seconds
        
        self.reset_analysis_ui()
        self.status_bar.showMessage("Analysis cancelled")
    
    def on_progress_updated(self, message: str, progress: float):
        """Handle progress updates"""
        self.progress_bar.setValue(int(progress * 100))
        self.progress_bar.setFormat(f"{progress*100:.1f}% - {message}")
        self.status_bar.showMessage(message)
    
    def on_analysis_complete(self, analysis_data: List):
        """Handle analysis completion with optional statistics"""
        # analysis_data è [results, stats] dove stats può essere None
        if len(analysis_data) >= 2:
            results, stats = analysis_data[0], analysis_data[1]
        else:
            results, stats = analysis_data, None
            
        self.current_results = results
        self.populate_results_table(results)
        
        # Mostra statistiche Hybrid se disponibili
        if stats:
            self.display_hybrid_statistics(stats)
        self.generate_summary_report(results)

        self.reset_analysis_ui()
    
    def display_hybrid_statistics(self, stats: dict):
        """Display Hybrid Detector statistics in results"""
        # Aggiungi le statistiche come un messaggio informativo nella console
        stats_text = f"\n🔬 HYBRID ANALYSIS STATISTICS:\n"
        stats_text += f"   • Pattern Analysis Time: {stats.get('analysis_time_pattern', 0):.2f}s\n"
        stats_text += f"   • Capstone Analysis Time: {stats.get('analysis_time_capstone', 0):.2f}s\n"
        stats_text += f"   • Total Analysis Time: {stats.get('total_analysis_time', 0):.2f}s\n"
        stats_text += f"   • Sections Screened: {stats.get('sections_screened', 0)}\n"
        stats_text += f"   • Sections Deep-Analyzed: {stats.get('sections_analyzed_capstone', 0)}\n"
        stats_text += f"   • Capstone Efficiency: {stats.get('capstone_efficiency', 0):.1f}%\n"
        stats_text += f"   • Pattern Matches: {stats.get('pattern_matches_found', 0)}\n"
        stats_text += f"   • Capstone Confirmations: {stats.get('capstone_confirmations', 0)}\n"
        stats_text += f"   • Confirmation Rate: {stats.get('confirmation_rate', 0):.1f}%\n"
        
        # Mostra nel log console
        if hasattr(self, 'log_console'):
            self.log_console.append(stats_text)
        
        # Aggiorna anche lo status bar con informazioni chiave
        efficiency = stats.get('capstone_efficiency', 0)
        total_time = stats.get('total_analysis_time', 0)
        self.status_bar.showMessage(
            f"✅ Hybrid Analysis Complete - {efficiency:.1f}% efficiency, {total_time:.2f}s total"
        )
        
        # Update stats
        detection_count = len(result)
        self.stats_label.setText("Analysis complete!")
        self.detection_count_label.setText(f"{detection_count} detections")
        
        self.status_bar.showMessage(f"Analysis complete - {detection_count} detections found")
        
        # Switch to results tab
        self.results_tabs.setCurrentIndex(0)
        
        if detection_count == 0:
            QMessageBox.information(self, "Analysis Complete", 
                "No anti-reversing techniques detected.\n\n"
                "This could indicate:\n"
                "• Clean, unprotected binary\n"
                "• Advanced evasion techniques not covered\n"
                "• Binary format not fully supported")
    
    def on_analysis_error(self, error_message: str):
        """Handle analysis error"""
        self.reset_analysis_ui()
        self.status_bar.showMessage("Analysis failed")
        QMessageBox.critical(self, "Analysis Error", f"Analysis failed:\n\n{error_message}")
    
    def reset_analysis_ui(self):
        """Reset UI after analysis"""
        self.analyze_button.setVisible(True)
        self.cancel_button.setVisible(False)
        self.progress_bar.setVisible(False)
        self.analyze_button.setEnabled(True)
    
    def populate_results_table(self, results: List[DetectionResult]):
        """Populate results table with detection results"""
        self.results_table.setRowCount(len(results))
        
        for row, result in enumerate(results):
            # Detector name
            self.results_table.setItem(row, 0, QTableWidgetItem(result.detector_name.replace("Detector", "")))
            
            # Technique
            self.results_table.setItem(row, 1, QTableWidgetItem(result.technique_name))
            
            # Address
            addr_item = QTableWidgetItem(f"0x{result.address:08x}")
            self.results_table.setItem(row, 2, addr_item)
            
            # Description
            self.results_table.setItem(row, 3, QTableWidgetItem(result.description))
            
            # Evidence
            evidence = result.evidence if result.evidence else "N/A"
            self.results_table.setItem(row, 4, QTableWidgetItem(evidence))
    
    def generate_summary_report(self, results: List[DetectionResult]):
        """Generate comprehensive summary report"""
        import datetime
        
        # Get binary information
        binary_name = os.path.basename(self.current_binary_path) if self.current_binary_path else 'Unknown'
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Generate header
        report = f"""
{'='*70}
🔍 CONAN - ANTI-REVERSING DETECTION FRAMEWORK
{'='*70}

ANALYSIS SUMMARY:
Target Binary: {binary_name}
Analysis Date: {timestamp}
Framework Version: 1.0
Detectors Used: AntiDebug, Packer, VM Evasion, Anti-Disassembly

"""
        
        if not results:
            report += """
RISULTATI RILEVAMENTO:
🟢 CLEAN – Nessuna tecnica di anti-reversing rilevata

INTERPRETAZIONE:
Questo file non sembra utilizzare tecniche comuni di anti-analisi, packing o 
evasione da macchine virtuali. Tuttavia, questo **non garantisce** l’assenza di:
• Tecniche di protezione custom o non documentate
• Metodi avanzati di offuscamento  
• Tecniche di evasione zero-day

RACCOMANDAZIONI:
• Procedere con un’analisi statica e dinamica standard
• Monitorare eventuali comportamenti anomali in fase di esecuzione
• Convalidare i risultati con altri strumenti di analisi
• Considerare un’analisi manuale di reverse engineering se necessario

NOTE TECNICHE:
• Tutte le principali categorie di detector non hanno prodotto match
• Il binario potrebbe essere effettivamente pulito o utilizzare tecniche di evasione sofisticate
• Consigliato testare anche con sample noti malevoli per verificare la funzionalità dei rilevatori
"""
        else:
            # Group results by detector and technique
            by_detector = {}
            by_technique = {}
            
            for result in results:
                # Group by detector
                detector = result.detector_name
                if detector not in by_detector:
                    by_detector[detector] = []
                by_detector[detector].append(result)
                
                # Group by technique
                technique = result.technique_name
                if technique not in by_technique:
                    by_technique[technique] = []
                by_technique[technique].append(result)
            
            # Calculate comprehensive statistics
            total_detections = len(results)
            high_confidence = len([r for r in results if r.confidence >= 0.8])
            medium_confidence = len([r for r in results if 0.5 <= r.confidence < 0.8])
            low_confidence = len([r for r in results if r.confidence < 0.5])
            avg_confidence = sum(r.confidence for r in results) / len(results)
            max_confidence = max(r.confidence for r in results)
            
            # Risk assessment
            report += "DETECTION RESULTS:\n"
            if high_confidence >= 10:
                report += "🔴 CRITICAL THREAT - Heavily protected binary with multiple sophisticated techniques\n"
                risk_level = "CRITICAL"
            elif high_confidence >= 5:
                report += "🟠 HIGH THREAT - Multiple anti-analysis techniques detected\n"  
                risk_level = "HIGH"
            elif high_confidence >= 2 or total_detections >= 8:
                report += "🟡 MODERATE THREAT - Several evasion techniques present\n"
                risk_level = "MODERATE"
            elif high_confidence >= 1 or total_detections >= 3:
                report += "🟡 LOW-MODERATE THREAT - Some anti-analysis techniques detected\n"
                risk_level = "LOW-MODERATE"
            else:
                report += "🟢 LOW THREAT - Few or weak evasion techniques\n"
                risk_level = "LOW"
            
            report += f"""
STATISTICAL OVERVIEW:
• Total Detections: {total_detections}
• High Confidence (≥80%): {high_confidence} detections  
• Medium Confidence (50-79%): {medium_confidence} detections
• Low Confidence (<50%): {low_confidence} detections
• Average Confidence: {avg_confidence*100:.1f}%
• Maximum Confidence: {max_confidence*100:.1f}%
• Risk Level: {risk_level}

"""
            
            # Detector breakdown
            report += "DETECTOR BREAKDOWN:\n"
            report += "-" * 50 + "\n"
            
            detector_icons = {
                "AntiDebugDetector": "🚫", 
                "PackerDetector": "📦", 
                "VMDetector": "🖥️", 
                "AntiDisasmDetector": "🔧",
                "CryptoDetector": "🔐",
                "NetworkDetector": "🌐"
            }
            
            for detector, detections in sorted(by_detector.items()):
                detector_name = detector.replace("Detector", "")
                icon = detector_icons.get(detector, "🔍")
                max_conf = max(d.confidence for d in detections)
                avg_conf = sum(d.confidence for d in detections) / len(detections)
                
                report += f"\n{icon} {detector_name.upper()} DETECTOR:\n"
                report += f"   Detections: {len(detections)}\n"
                report += f"   Max Confidence: {max_conf*100:.1f}%\n"
                report += f"   Avg Confidence: {avg_conf*100:.1f}%\n"
                
                # Show top techniques for this detector
                technique_counts = {}
                for detection in detections:
                    tech = detection.technique_name
                    if tech not in technique_counts:
                        technique_counts[tech] = []
                    technique_counts[tech].append(detection)
                
                report += "   Top Techniques:\n"
                sorted_techs = sorted(technique_counts.items(), 
                                    key=lambda x: len(x[1]), reverse=True)
                
                for tech, tech_detections in sorted_techs[:3]:
                    report += f"     • {tech}: {len(tech_detections)} occurrence(s)\n"
                
                if len(sorted_techs) > 3:
                    remaining = len(sorted_techs) - 3
                    report += f"     ... and {remaining} more technique(s)\n"
            
            # Top techniques overall
            report += f"\nTOP TECHNIQUES DETECTED:\n"
            report += "-" * 50 + "\n"
            
            sorted_techniques = sorted(by_technique.items(), 
                                     key=lambda x: len(x[1]), 
                                     reverse=True)
            
            for i, (technique, tech_results) in enumerate(sorted_techniques[:8], 1):
                count = len(tech_results)
                
                report += f"{i:2d}. {technique}\n"
                report += f"    Occurrences: {count}\n"
                
                # Show sample evidence
                best_result = tech_results[0]  # Just take the first result
                if best_result.evidence:
                    evidence = best_result.evidence[:80] + "..." if len(best_result.evidence) > 80 else best_result.evidence
                    report += f"    Sample Evidence: {evidence}\n"
                report += "\n"
            
            # Recommendations based on findings
            report += "ANALYSIS RECOMMENDATIONS:\n"
            report += "-" * 50 + "\n"
            
            if "AntiDebugDetector" in by_detector:
                count = len(by_detector["AntiDebugDetector"])
                report += f"🚫 ANTI-DEBUG TECHNIQUES ({count} detected):\n"
                report += "   • Use hardware-assisted debugging (Intel PT, etc.)\n"
                report += "   • Apply anti-anti-debug patches or plugins\n"
                report += "   • Consider kernel-mode debugging approaches\n"
                report += "   • Use debugging-resistant analysis environments\n\n"
            
            if "PackerDetector" in by_detector:
                count = len(by_detector["PackerDetector"])
                report += f"📦 PACKING/COMPRESSION ({count} detected):\n"
                report += "   • Use automated unpacking tools (UPX, etc.)\n"
                report += "   • Analyze entropy and section characteristics\n" 
                report += "   • Consider dynamic unpacking approaches\n"
                report += "   • Check for multiple packing layers\n\n"
            
            if "VMDetector" in by_detector:
                count = len(by_detector["VMDetector"])
                report += f"🖥️ VM EVASION ({count} detected):\n"
                report += "   • Use bare-metal analysis systems when possible\n"
                report += "   • Employ VM-aware analysis techniques\n"
                report += "   • Consider cloud-based sandboxes with evasion resistance\n"
                report += "   • Use anti-evasion patches for VMs\n\n"
            
            report += "GENERAL ANALYSIS STRATEGY:\n"
            if risk_level in ["CRITICAL", "HIGH"]:
                report += "⚠️  HIGH-SECURITY APPROACH REQUIRED:\n"
                report += "   • Use isolated, dedicated analysis environment\n"
                report += "   • Employ multiple complementary analysis techniques\n"
                report += "   • Consider professional malware analysis tools\n"
                report += "   • Document all evasion attempts for threat intelligence\n\n"
            else:
                report += "📊 STANDARD ANALYSIS APPROACH:\n"
                report += "   • Proceed with standard static/dynamic analysis\n"
                report += "   • Cross-validate findings with multiple tools\n"
                report += "   • Monitor for unexpected runtime behavior\n"
                report += "   • Consider manual reverse engineering if needed\n\n"
        
        # Always add technical details section
        if results:
            report += "DETAILED TECHNICAL FINDINGS:\n"
            report += "=" * 50 + "\n"
            
            for i, result in enumerate(results, 1):
                report += f"\n[{i:03d}] {result.detector_name.replace('Detector', '').upper()} - {result.technique_name}\n"
                report += f"      Address: 0x{result.address:08x}\n"  
                report += f"      Description: {result.description}\n"
                
                if result.evidence:
                    # Format evidence nicely
                    evidence = result.evidence.strip()
                    if len(evidence) > 200:
                        evidence = evidence[:200] + "..."
                    report += f"      Evidence: {evidence}\n"
                
                if result.metadata:
                    # Show key metadata
                    meta_items = []
                    for k, v in result.metadata.items():
                        if k not in ['detector_name', 'technique_name', 'description']:
                            if isinstance(v, (str, int, float, bool)):
                                meta_items.append(f"{k}={v}")
                    if meta_items:
                        meta_str = ", ".join(meta_items[:3])
                        if len(meta_items) > 3:
                            meta_str += "..."
                        report += f"      Metadata: {meta_str}\n"
        
        report += "\n" + "="*70 + "\n"
        report += "End of CONAN Analysis Report\n"
        report += "="*70
        
        self.summary_text.setPlainText(report)
    
    def on_result_double_click(self, item):
        """Handle double-click on result item"""
        row = item.row()
        if row < len(self.current_results):
            result = self.current_results[row]
            
            # Show detailed information
            details = f"""
DETECTION DETAILS
=================

Detector: {result.detector_name}
Technique: {result.technique_name}
Address: 0x{result.address:08x}

Description:
{result.description}
"""
            
            if result.evidence:
                details += f"\nEvidence:\n{result.evidence}"
            
            if result.metadata:
                details += "\n\nMetadata:\n"
                for key, value in result.metadata.items():
                    details += f"  {key}: {value}\n"
            
            QMessageBox.information(self, "Detection Details", details)
    
    def export_report(self):
        """Export analysis report"""
        if not self.current_results:
            QMessageBox.warning(self, "Warning", "No analysis results to export.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Report",
            f"CONAN_Report_{os.path.basename(self.current_binary_path).replace('.', '_')}.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.summary_text.toPlainText())
                
                QMessageBox.information(self, "Export Complete", f"Report exported to:\n{file_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export report:\n{str(e)}")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
CONAN - Framework di Rilevamento Anti-Reversing
Versione 1.0.0

Un framework avanzato per l’individuazione di tecniche di anti-debugging,
packing, evasione da macchine virtuali.

Sviluppato come parte di un progetto di tesi in Informatica
(Laurea Triennale – Università di Bari).
Autore: Cannone Giuseppe
Anno: 2025

Caratteristiche principali:
• Interfaccia sviluppata in PyQt6
• Architettura modulare dei detector
• Analisi dei file completa
• Report dettagliati esportabili

© 2025 Cannone Giuseppe — CONAN Framework
"""
        
        QMessageBox.about(self, "About CONAN", about_text)
    
    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter event"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def dropEvent(self, event: QDropEvent):
        """Handle drop event"""
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        if files:
            self.load_binary_file(files[0])
    
    def apply_dark_theme(self):
        """Apply dark theme styling"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a1a;
                color: #ffffff;
            }
            
            #sidebar {
                background-color: #1a1a1a;
                border-right: 1px solid #404040;
            }
            
            #logoFrame {
                background-color: #2d2d2d;
                border: 1px solid #404040;
                border-radius: 12px;
                padding: 15px;
                margin-bottom: 10px;
            }
            
            #logoTitle {
                font-size: 24px;
                font-weight: bold;
                color: #60a5fa;
                margin: 0px;
            }
            
            #logoSubtitle {
                font-size: 12px;
                color: #9ca3af;
                margin: 0px;
            }
            
            #logoVersion {
                font-size: 10px;
                color: #6b7280;
                margin: 0px;
            }
            
            #modernHeader {
                background-color: #2d2d2d;
                border: 1px solid #404040;
                border-radius: 8px;
                margin-bottom: 15px;
            }
            
            #currentFileLabel {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
            }
            
            #fileDetailsLabel {
                font-size: 12px;
                color: #9ca3af;
            }
            
            #statsLabel {
                font-size: 14px;
                font-weight: bold;
                color: #10b981;
            }
            
            #detectionCountLabel {
                font-size: 12px;
                color: #9ca3af;
            }
            
            #contentArea {
                background-color: #1e1e1e;
            }
            
            #titleLabel {
                color: #ffffff;
                font-weight: bold;
            }
            
            #subtitleLabel {
                color: #cccccc;
                font-style: italic;
            }
            
            #statsLabel {
                color: #4ade80;
                font-weight: bold;
            }
            
            #filePathLabel {
                background-color: #2d2d2d;
                color: #cccccc;
                font-size: 12px;
            }
            
            #browseButton {
                background-color: #3b82f6;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            
            #browseButton:hover {
                background-color: #2563eb;
            }
            
            #analyzeButton {
                background-color: #16a34a;
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 14px;
            }
            
            #analyzeButton:hover {
                background-color: #15803d;
            }
            
            #analyzeButton:disabled {
                background-color: #6b7280;
            }
            
            #cancelButton {
                background-color: #dc2626;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
            }
            
            #cancelButton:hover {
                background-color: #b91c1c;
            }
            
            #darkModeButton {
                background-color: #f59e0b;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            
            #darkModeButton:hover {
                background-color: #d97706;
            }
            
            #progressBar {
                border: 1px solid #404040;
                border-radius: 6px;
                text-align: center;
                color: #ffffff;
                background-color: #2d2d2d;
            }
            
            #progressBar::chunk {
                background-color: #3b82f6;
                border-radius: 5px;
            }
            
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #ffffff;
                margin-top: 10px;
                border: 2px solid #404040;
                border-radius: 8px;
                padding-top: 10px;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px 0 8px;
                color: #ffffff;
            }
            
            QTabWidget::pane {
                border: 1px solid #404040;
                border-radius: 6px;
                background-color: #2d2d2d;
                padding: 10px;
            }
            
            QTabBar::tab {
                background-color: #404040;
                color: #cccccc;
                border: 1px solid #555555;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                font-weight: normal;
            }
            
            QTabBar::tab:selected {
                background-color: #2d2d2d;
                color: #3b82f6;
                border-bottom: 1px solid #2d2d2d;
                font-weight: bold;
            }
            
            QTabBar::tab:hover:!selected {
                background-color: #555555;
                color: #3b82f6;
            }
            
            QTableWidget {
                background-color: #2d2d2d;
                alternate-background-color: #404040;
                selection-background-color: #3b82f6;
                selection-color: white;
                border: 1px solid #404040;
                border-radius: 6px;
                color: #ffffff;
            }
            
            QHeaderView::section {
                background-color: #404040;
                color: #ffffff;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #555555;
                font-weight: bold;
            }
            
            #summaryText, #binaryInfoText {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #404040;
                border-radius: 6px;
                padding: 10px;
                font-family: 'Consolas', 'Monaco', monospace;
                selection-background-color: #3b82f6;
                selection-color: white;
            }
            
            #configTitle {
                font-size: 13px;
                font-weight: bold;
                color: #ffffff;
                margin-bottom: 5px;
            }
            
            #detectorCheck {
                font-size: 12px;
                font-weight: normal;
                color: #ffffff;
                padding: 4px 0px;
                margin: 2px 0px;
            }
            
            QCheckBox {
                font-weight: normal;
                color: #ffffff;
            }
            
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                margin-right: 8px;
            }
            
            QCheckBox::indicator:unchecked {
                border: 2px solid #6b7280;
                border-radius: 4px;
                background-color: #2d2d2d;
            }
            
            QCheckBox::indicator:checked {
                border: 2px solid #3b82f6;
                border-radius: 4px;
                background-color: #3b82f6;
            }
            
            QCheckBox::indicator:disabled {
                border: 2px solid #404040;
                background-color: #1a1a1a;
            }
            
            QLabel {
                color: #ffffff;
            }
            
            QMenuBar {
                background-color: #1a1a1a;
                color: #ffffff;
                border-bottom: 1px solid #404040;
            }
            
            QMenuBar::item {
                background-color: transparent;
                padding: 6px 12px;
            }
            
            QMenuBar::item:selected {
                background-color: #3b82f6;
                color: white;
                border-radius: 4px;
            }
            
            QMenu {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #404040;
                border-radius: 6px;
            }
            
            QMenu::item {
                padding: 8px 16px;
            }
            
            QMenu::item:selected {
                background-color: #3b82f6;
                color: white;
            }
            
            QStatusBar {
                background-color: #1a1a1a;
                color: #cccccc;
                border-top: 1px solid #404040;
            }
        """)


def main():
    """Main function to run the GUI"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("CONAN")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("CONAN Framework")
    
    # Create and show main window
    window = ConanMainWindow()
    window.show()
    
    # Run application
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
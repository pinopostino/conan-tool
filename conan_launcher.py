#!/usr/bin/env python3
"""
CONAN Framework - Professional Launcher
Advanced launcher with Detective Conan branding and system checks
"""

import sys
import os
from pathlib import Path
import subprocess
import time

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
    QLabel, QProgressBar, QFrame, QTextEdit, QSplashScreen
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QPixmap, QFont, QIcon, QPainter, QColor


class SystemCheckWorker(QThread):
    """Worker thread for system checks"""
    progress_updated = pyqtSignal(str, int)
    check_complete = pyqtSignal(bool, str)
    
    def run(self):
        """Run system checks"""
        try:
            checks = [
                ("Checking Python version...", self.check_python),
                ("Checking PyQt6 installation...", self.check_pyqt6),
                ("Checking CONAN framework...", self.check_conan),
                ("Verifying pattern detectors...", self.check_detectors),
                ("Loading GUI components...", self.check_gui),
            ]
            
            total_checks = len(checks)
            
            for i, (message, check_func) in enumerate(checks):
                self.progress_updated.emit(message, int((i / total_checks) * 100))
                time.sleep(0.5)  # Visual delay for user experience
                
                success, error = check_func()
                if not success:
                    self.check_complete.emit(False, f"Failed: {message}\n{error}")
                    return
            
            self.progress_updated.emit("System checks complete!", 100)
            time.sleep(0.5)
            self.check_complete.emit(True, "All system checks passed!")
            
        except Exception as e:
            self.check_complete.emit(False, f"System check error: {str(e)}")
    
    def check_python(self):
        """Check Python version"""
        try:
            if sys.version_info < (3, 8):
                return False, f"Python 3.8+ required, found {sys.version_info.major}.{sys.version_info.minor}"
            return True, ""
        except Exception as e:
            return False, str(e)
    
    def check_pyqt6(self):
        """Check PyQt6 installation"""
        try:
            from PyQt6 import QtWidgets
            return True, ""
        except ImportError as e:
            return False, f"PyQt6 not installed: {str(e)}"
    
    def check_conan(self):
        """Check CONAN framework"""
        try:
            from core.detection_engine import DetectionEngine
            return True, ""
        except ImportError as e:
            return False, f"CONAN framework not found: {str(e)}"
    
    def check_detectors(self):
        """Check pattern-based detector modules"""
        try:
            from detectors.anti_debug_detector import AntiDebugDetector
            from detectors.packer_detector import PackerDetector
            from detectors.vm_detector import VMDetector
            
            return True, ""
        except ImportError as e:
            return False, f"Detector modules missing: {str(e)}"
    
    def check_gui(self):
        """Check GUI components"""
        try:
            from gui.main_window import ConanMainWindow
            return True, ""
        except ImportError as e:
            return False, f"GUI components missing: {str(e)}"


class ConanSplashScreen(QSplashScreen):
    """Custom splash screen with Detective Conan image"""
    
    def __init__(self, pixmap):
        super().__init__(pixmap, Qt.WindowType.WindowStaysOnTopHint)
        
        # Set professional font for loading messages
        self.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
    
    def showMessage(self, message, alignment=Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignCenter, color=QColor(255, 255, 255)):
        """Show message on splash screen with better styling"""
        # Use a more prominent white color with shadow effect
        super().showMessage(message, alignment, QColor(255, 255, 255))
        self.repaint()
    
    def drawContents(self, painter):
        """Custom drawing for better text visibility"""
        super().drawContents(painter)
        
        # Add custom text styling if needed
        painter.setPen(QColor(0, 0, 0, 100))  # Semi-transparent black shadow
        painter.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))


class ConanLauncher(QWidget):
    """Professional launcher for CONAN Framework"""
    
    def __init__(self):
        super().__init__()
        self.system_check_worker = None
        self.setup_ui()
        self.setup_styling()
    
    def setup_ui(self):
        """Setup launcher UI"""
        self.setWindowTitle("CONAN Framework Launcher")
        self.setFixedSize(600, 500)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        
        # Set application icon
        try:
            icon_path = Path(__file__).parent / "conanImmagine.png"
            if icon_path.exists():
                self.setWindowIcon(QIcon(str(icon_path)))
        except Exception:
            pass
        
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Header with Detective Conan image
        self.setup_header(main_layout)
        
        # Content area
        self.setup_content(main_layout)
        
        # Footer with buttons
        self.setup_footer(main_layout)
        
        # Center window on screen
        self.center_window()
    
    def setup_header(self, parent_layout):
        """Setup header with Detective Conan image"""
        header_frame = QFrame()
        header_frame.setObjectName("headerFrame")
        header_frame.setFixedHeight(200)
        
        header_layout = QVBoxLayout(header_frame)
        header_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Detective Conan image
        try:
            image_path = Path(__file__).parent / "conanImmagine.png"
            if image_path.exists():
                image_label = QLabel()
                pixmap = QPixmap(str(image_path))
                
                # Scale image for header
                scaled_pixmap = pixmap.scaled(140, 140, Qt.AspectRatioMode.KeepAspectRatio,
                                            Qt.TransformationMode.SmoothTransformation)
                image_label.setPixmap(scaled_pixmap)
                image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                header_layout.addWidget(image_label)
        except Exception:
            # Fallback text
            title_label = QLabel("🕵️ CONAN")
            title_label.setObjectName("titleLabel")
            title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            header_layout.addWidget(title_label)
        
        # Framework title
        subtitle_label = QLabel("Anti-Reversing Detection Framework")
        subtitle_label.setObjectName("subtitleLabel")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(subtitle_label)
        
        parent_layout.addWidget(header_frame)
    
    def setup_content(self, parent_layout):
        """Setup content area"""
        content_frame = QFrame()
        content_frame.setObjectName("contentFrame")
        
        content_layout = QVBoxLayout(content_frame)
        content_layout.setContentsMargins(40, 20, 40, 20)
        content_layout.setSpacing(15)
        
        # Framework info
        info_label = QLabel("Advanced Binary Analysis Tool")
        info_label.setObjectName("infoLabel")
        info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content_layout.addWidget(info_label)
        
        # Features - Pattern-based detection only
        features = [
            "🚫 Anti-Debug Detection (Pattern-based)",
            "📦 Packer Detection (No false positives)", 
            "🖥️ VM Evasion Detection (Comprehensive)",
            "🔧 Anti-Disassembly Detection (Fuzzy matching)"
        ]
        
        for feature in features:
            feature_label = QLabel(feature)
            feature_label.setObjectName("featureLabel")
            feature_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            content_layout.addWidget(feature_label)
        
        # Progress bar for system checks
        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("progressBar")
        self.progress_bar.setVisible(False)
        self.progress_bar.setTextVisible(True)
        content_layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Ready to launch CONAN Framework")
        self.status_label.setObjectName("statusLabel")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content_layout.addWidget(self.status_label)
        
        parent_layout.addWidget(content_frame)
    
    def setup_footer(self, parent_layout):
        """Setup footer with action buttons"""
        footer_frame = QFrame()
        footer_frame.setObjectName("footerFrame")
        footer_frame.setFixedHeight(80)
        
        footer_layout = QHBoxLayout(footer_frame)
        footer_layout.setContentsMargins(40, 15, 40, 15)
        
        # System check button
        self.check_button = QPushButton("🔧 System Check")
        self.check_button.setObjectName("checkButton")
        self.check_button.setFixedSize(130, 40)
        self.check_button.clicked.connect(self.run_system_check)
        footer_layout.addWidget(self.check_button)
        
        footer_layout.addStretch()
        
        # Launch button
        self.launch_button = QPushButton("🚀 Launch CONAN")
        self.launch_button.setObjectName("launchButton")
        self.launch_button.setFixedSize(150, 40)
        self.launch_button.clicked.connect(self.launch_conan)
        footer_layout.addWidget(self.launch_button)
        
        footer_layout.addStretch()
        
        # Exit button
        self.exit_button = QPushButton("❌ Exit")
        self.exit_button.setObjectName("exitButton")
        self.exit_button.setFixedSize(100, 40)
        self.exit_button.clicked.connect(self.close)
        footer_layout.addWidget(self.exit_button)
        
        parent_layout.addWidget(footer_frame)
    
    def setup_styling(self):
        """Setup launcher styling"""
        self.setStyleSheet("""
            QWidget {
                background-color: #1a1a1a;
                color: #ffffff;
                font-family: 'Segoe UI', 'Arial', sans-serif;
            }
            
            #headerFrame {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d3748, stop:1 #1a202c);
                border-bottom: 2px solid #4299e1;
            }
            
            #contentFrame {
                background-color: #2d3748;
            }
            
            #footerFrame {
                background-color: #1a202c;
                border-top: 1px solid #4a5568;
            }
            
            #titleLabel {
                font-size: 28px;
                font-weight: bold;
                color: #4299e1;
            }
            
            #subtitleLabel {
                font-size: 16px;
                font-weight: normal;
                color: #a0aec0;
                margin-top: 5px;
            }
            
            #infoLabel {
                font-size: 18px;
                font-weight: bold;
                color: #4299e1;
                margin-bottom: 10px;
            }
            
            #featureLabel {
                font-size: 14px;
                color: #e2e8f0;
                padding: 2px 0px;
            }
            
            #statusLabel {
                font-size: 14px;
                color: #68d391;
                font-weight: bold;
                margin-top: 10px;
            }
            
            #progressBar {
                height: 25px;
                border: 2px solid #4a5568;
                border-radius: 12px;
                background-color: #2d3748;
                text-align: center;
                color: #ffffff;
                font-weight: bold;
            }
            
            #progressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4299e1, stop:1 #3182ce);
                border-radius: 10px;
            }
            
            QPushButton {
                font-size: 13px;
                font-weight: bold;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
            }
            
            #launchButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #48bb78, stop:1 #38a169);
                color: white;
            }
            
            #launchButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #38a169, stop:1 #2f855a);
            }
            
            #checkButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4299e1, stop:1 #3182ce);
                color: white;
            }
            
            #checkButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #3182ce, stop:1 #2c5282);
            }
            
            #exitButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #f56565, stop:1 #e53e3e);
                color: white;
            }
            
            #exitButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #e53e3e, stop:1 #c53030);
            }
            
            QPushButton:pressed {
                margin-top: 1px;
            }
        """)
    
    def center_window(self):
        """Center window on screen"""
        screen = QApplication.primaryScreen().geometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)
    
    def run_system_check(self):
        """Run comprehensive system check"""
        self.check_button.setEnabled(False)
        self.launch_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Running system checks...")
        
        # Start system check worker
        self.system_check_worker = SystemCheckWorker()
        self.system_check_worker.progress_updated.connect(self.on_check_progress)
        self.system_check_worker.check_complete.connect(self.on_check_complete)
        self.system_check_worker.start()
    
    def on_check_progress(self, message, progress):
        """Handle check progress update"""
        self.progress_bar.setValue(progress)
        self.status_label.setText(message)
    
    def on_check_complete(self, success, message):
        """Handle check completion"""
        self.progress_bar.setVisible(False)
        self.check_button.setEnabled(True)
        self.launch_button.setEnabled(True)
        
        if success:
            self.status_label.setText("✅ System check passed! Ready to launch CONAN")
            self.status_label.setStyleSheet("color: #68d391; font-weight: bold;")
        else:
            self.status_label.setText(f"❌ System check failed: {message}")
            self.status_label.setStyleSheet("color: #f56565; font-weight: bold;")
            self.launch_button.setEnabled(False)
    
    def launch_conan(self):
        """Launch CONAN Framework"""
        try:
            self.status_label.setText("🚀 Launching CONAN Framework...")
            
            # Launch GUI in separate process for better isolation
            try:
                python_exe = sys.executable
                gui_script = Path(__file__).parent / "gui_launcher.py"
                
                # Check if gui_launcher.py exists, otherwise create it
                if not gui_script.exists():
                    self.create_gui_launcher_script()
                
                # Launch GUI as separate process with debugging
                process = subprocess.Popen([python_exe, str(gui_script)], 
                                         cwd=str(Path(__file__).parent),
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
                
                # Check if process started successfully
                if process.poll() is None:  # Process is running
                    self.status_label.setText("✅ CONAN Framework launched successfully!")
                    self.status_label.setStyleSheet("color: #68d391; font-weight: bold;")
                    
                    # Close launcher after GUI is confirmed running
                    QTimer.singleShot(3000, self.close)
                else:
                    # Process failed to start
                    stdout, stderr = process.communicate()
                    error_msg = stderr.decode() if stderr else stdout.decode()
                    raise Exception(f"GUI process failed: {error_msg}")
                
            except Exception as launch_error:
                # Fallback: try direct import in same process
                self.status_label.setText("🔄 Fallback: launching in same process...")
                try:
                    from gui.main_window import ConanMainWindow
                    
                    # Create main window in same process
                    self.main_window = ConanMainWindow()
                    self.main_window.show()
                    
                    # Hide launcher but keep it alive
                    self.hide()
                    
                    # Don't close launcher - let it stay alive to keep GUI running
                    self.status_label.setText("✅ CONAN Framework launched (direct mode)!")
                    
                except Exception as direct_error:
                    self.status_label.setText(f"❌ All launch methods failed: {str(direct_error)}")
                    self.status_label.setStyleSheet("color: #f56565; font-weight: bold;")
        
        except Exception as e:
            self.status_label.setText(f"❌ Launch failed: {str(e)}")
            self.status_label.setStyleSheet("color: #f56565; font-weight: bold;")
    
    def create_gui_launcher_script(self):
        """Create gui_launcher.py script for launching main GUI"""
        gui_launcher_content = '''#!/usr/bin/env python3
"""
GUI Launcher for CONAN Framework
"""
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from PyQt6.QtWidgets import QApplication
from gui.main_window import ConanMainWindow

def main():
    """Launch CONAN GUI"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("CONAN Framework")
    app.setApplicationVersion("1.0.0")
    
    # Create and show main window
    window = ConanMainWindow()
    window.show()
    
    # Run application
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
'''
        
        gui_script_path = Path(__file__).parent / "gui_launcher.py"
        try:
            with open(gui_script_path, 'w', encoding='utf-8') as f:
                f.write(gui_launcher_content)
        except Exception as e:
            print(f"Error creating GUI launcher script: {e}")
    
    def close_launcher_safely(self):
        """Safely close launcher when main window is destroyed"""
        try:
            # Give a small delay before closing
            QTimer.singleShot(100, self.close)
        except Exception:
            pass


def main():
    """Main function - avvia direttamente come FIFA"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("CONAN Framework")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("CONAN Framework")
    
    # Set application icon
    try:
        icon_path = Path(__file__).parent / "conanImmagine.png"
        if icon_path.exists():
            app.setWindowIcon(QIcon(str(icon_path)))
    except Exception:
        pass
    
    # Show splash screen e poi avvia GUI direttamente
    try:
        splash_path = Path(__file__).parent / "conanImmagine.png"
        if splash_path.exists():
            # Create splash screen
            splash_pixmap = QPixmap(str(splash_path))
            scaled_splash = splash_pixmap.scaled(400, 400, Qt.AspectRatioMode.KeepAspectRatio,
                                               Qt.TransformationMode.SmoothTransformation)
            
            splash = ConanSplashScreen(scaled_splash)
            splash.show()
            
            # Progressive loading messages come FIFA
            splash.showMessage("Loading CONAN Framework...", Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignCenter)
            QApplication.processEvents()
            
            QTimer.singleShot(800, lambda: splash.showMessage("Initializing Detective System...", Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignCenter))
            QTimer.singleShot(1600, lambda: splash.showMessage("Loading Analysis Tools...", Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignCenter))
            QTimer.singleShot(2400, lambda: splash.showMessage("Loading Detectors...", Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignCenter))
            QTimer.singleShot(3200, lambda: splash.showMessage("Starting Application...", Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignCenter))
            
            # Dopo splash, avvia GUI direttamente
            QTimer.singleShot(4000, lambda: launch_main_gui(splash, app))
        else:
            # No splash, avvia GUI direttamente
            launch_main_gui(None, app)
    except Exception:
        launch_main_gui(None, app)
    
    sys.exit(app.exec())


def launch_main_gui(splash, app):
    """Avvia la GUI principale dopo splash"""
    try:
        print("AVVIO GUI IN CORSO...")
        
        # Chiudi splash se esiste
        if splash:
            splash.close()
            print("Splash chiuso")
        
        # Import e avvia GUI
        from gui.main_window import ConanMainWindow
        print("Import GUI OK")
        
        # Crea e mostra finestra principale
        window = ConanMainWindow()
        print("Finestra creata")
        
        window.show()
        print("Finestra mostrata")
        
        # IMPORTANTE: mantieni il riferimento alla finestra nell'app
        app.main_window = window
        
    except Exception as e:
        print(f"ERRORE avvio GUI: {e}")
        import traceback
        traceback.print_exc()
        # Fallback: mostra launcher
        launcher = ConanLauncher()
        launcher.show()


if __name__ == "__main__":
    main()
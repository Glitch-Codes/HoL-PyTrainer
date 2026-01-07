import sys
import pymem
import utility
from AOBCheats.unlimited_fuel import UnlimitedFuel
from AOBCheats.no_reload import NoReload
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QCheckBox, QLabel, QGroupBox, QPushButton, QTextEdit)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont
import time

app_name = "High on Life"
abreviation = "HoL"
executible = "Oregon-Win64-Shipping.exe"

class TrainerThread(QThread):
    status_update = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    success_signal = pyqtSignal(str)
    log_output = pyqtSignal(str)
    cheat_available = pyqtSignal(str, bool)  # cheat_name, is_available
    
    def __init__(self):
        super().__init__()

        self.running = True
        self.no_reload_enabled = False
        self.unlimited_fuel_enabled = False
        
        self.process = None
        self.proc_handle = None
        self.base_address = None

        self.no_reload_addr = None
        self.no_reload = None
        self.unlimited_fuel_addr = None
        self.unlimited_fuel = None
        
    def run(self):
        try:
            # Initialize process
            self.process = pymem.Pymem(executible)
            gameModule = pymem.process.module_from_name(self.process.process_handle, executible).lpBaseOfDll
            self.proc_handle = self.process.process_handle
            self.base_address = self.process.base_address
            
            self.status_update.emit("Loading trainer...")
            self.log_output.emit(f"Found {abreviation} process - Base: {hex(self.base_address)}")
            
            if gameModule != self.base_address:
                self.error_signal.emit("Discrepancy between Game Module and Base Address")
                return

            # Initialize no reload
            self.log_output.emit(f"Scanning for No Reload address...")
            self.no_reload_addr = utility.aobScan(self.process, "89 87 E0 00 00 00 48 85 F6", executible)
            if self.no_reload_addr == None:
                self.log_output.emit("Failed to find No Reload address")
                self.cheat_available.emit("no_reload", False)
            else:
                self.log_output.emit("Found No Reload address: " + hex(self.no_reload_addr))
                self.cheat_available.emit("no_reload", True)
            self.no_reload = NoReload(self.process, executible, self.proc_handle, self.no_reload_addr)

            # Initialize unlimited fuel
            self.log_output.emit(f"Scanning for Unlimited Fuel address...")
            self.unlimited_fuel_addr = utility.aobScan(self.process, "F3 0F 11 81 D8 10 00 00", executible)
            if self.unlimited_fuel_addr == None:
                self.log_output.emit("Failed to find Unlimited Fuel address")
                self.cheat_available.emit("unlimited_fuel", False)
            else:
                self.log_output.emit("Found Unlimited Fuel address: " + hex(self.unlimited_fuel_addr))
                self.cheat_available.emit("unlimited_fuel", True)
            self.unlimited_fuel = UnlimitedFuel(self.process, executible, self.proc_handle, self.unlimited_fuel_addr)

            self.log_output.emit("Finished searching for addresses!")
            self.success_signal.emit("Trainer active! Have fun :)")
            
            # Main loop
            while self.running:
                try:
                    # Handle no reload
                    if self.no_reload_enabled and self.no_reload and not self.no_reload.enabled:
                        if self.no_reload.enable():
                            self.success_signal.emit("No Reload Activated!")
                        else:
                            self.error_signal.emit("Failed to enable No Reload")
                            self.no_reload_enabled = False
                    elif not self.no_reload_enabled and self.no_reload and self.no_reload.enabled:
                        self.no_reload.disable()
                        self.status_update.emit("No Reload Deactivated")

                    # Handle unlimited fuel
                    if self.unlimited_fuel_enabled and self.unlimited_fuel and not self.unlimited_fuel.enabled:
                        if self.unlimited_fuel.enable():
                            self.success_signal.emit("Unlimited Fuel Activated!")
                        else:
                            self.error_signal.emit("Failed to enable Unlimited Fuel")
                            self.unlimited_fuel_enabled = False
                    elif not self.unlimited_fuel_enabled and self.unlimited_fuel and self.unlimited_fuel.enabled:
                        self.unlimited_fuel.disable()
                        self.status_update.emit("Unlimited Fuel Deactivated")
                    
                    time.sleep(0.1)  # Reduced CPU usage
                    
                except Exception as e:
                    self.error_signal.emit(f"Runtime error: {str(e)}")
                    self.log_output.emit(f"Runtime error in trainer loop: {str(e)}")
                    time.sleep(1)
                    
        except Exception as e:
            self.error_signal.emit(f"Initialization error: {str(e)}")
    
    def stop(self):
        self.running = False
        # Disable no reload if enabled
        if self.no_reload and self.no_reload.enabled:
            self.no_reload.disable()
        # Disable unlimited fuel if enabled
        if self.unlimited_fuel and self.unlimited_fuel.enabled:
            self.unlimited_fuel.disable()
        self.wait()


class TrainerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.trainer_thread = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle(f"{app_name} - Trainer")
        self.setGeometry(100, 100, 400, 500)
        self.setStyleSheet("background-color: #2b2b2b; color: #ffffff;")
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        
        # Title
        title = QLabel(f"{app_name} - Trainer")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #ff6b6b; padding: 10px;")
        layout.addWidget(title)
        
        # Status label
        self.status_label = QLabel("Status: Not Connected")
        self.status_label.setStyleSheet("background-color: #1e1e1e; padding: 10px; border-radius: 5px;")
        layout.addWidget(self.status_label)
        
        # Cheats group
        cheats_group = QGroupBox("Cheats")
        cheats_group.setStyleSheet("""
            QGroupBox {
                border: 2px solid #444444;
                border-radius: 5px;
                margin-top: 10px;
                padding: 15px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        cheats_layout = QVBoxLayout()
        
        # No Reload checkbox
        self.no_reload_checkbox = QCheckBox("No Reload (Opcode Patch)")
        self.no_reload_checkbox.setStyleSheet("""
            QCheckBox {
                padding: 5px;
                font-size: 12px;
            }
            QCheckBox:disabled {
                color: #666666;
            }
        """)
        self.no_reload_checkbox.stateChanged.connect(self.toggle_no_reload)
        cheats_layout.addWidget(self.no_reload_checkbox)

        # Unlimited Fuel checkbox
        self.unlimited_fuel_checkbox = QCheckBox("Unlimited Fuel (Opcode Patch)")
        self.unlimited_fuel_checkbox.setStyleSheet("""
            QCheckBox {
                padding: 5px;
                font-size: 12px;
            }
            QCheckBox:disabled {
                color: #666666;
            }
        """)
        self.unlimited_fuel_checkbox.stateChanged.connect(self.toggle_unlimited_fuel)
        cheats_layout.addWidget(self.unlimited_fuel_checkbox)
        
        cheats_group.setLayout(cheats_layout)
        layout.addWidget(cheats_group)
        
        # Control buttons
        self.start_button = QPushButton("Start Trainer")
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #666666;
            }
        """)
        self.start_button.clicked.connect(self.start_trainer)
        layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Stop Trainer")
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
            QPushButton:disabled {
                background-color: #666666;
            }
        """)
        self.stop_button.clicked.connect(self.stop_trainer)
        self.stop_button.setEnabled(False)
        layout.addWidget(self.stop_button)
        
        # Console output area
        console_label = QLabel("Log Output:")
        console_label.setStyleSheet("color: #cccccc; font-size: 11px; margin-top: 10px;")
        layout.addWidget(console_label)
        
        self.console_text = QTextEdit()
        self.console_text.setReadOnly(True)
        self.console_text.setMaximumHeight(150)
        self.console_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #00ff00;
                border: 1px solid #444444;
                border-radius: 5px;
                padding: 5px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 10px;
            }
        """)
        layout.addWidget(self.console_text)
        
        layout.addStretch()
        
        # Credits
        credits = QLabel(f"Made for {abreviation} by Glitch • Github.com/Glitch-Codes")
        credits.setAlignment(Qt.AlignCenter)
        credits.setStyleSheet("color: #888888; font-size: 10px; padding: 10px;")
        layout.addWidget(credits)
        
        central_widget.setLayout(layout)
        
        # Disable checkboxes initially
        self.set_checkboxes_enabled(False)
    
    def start_trainer(self):
        self.trainer_thread = TrainerThread()
        self.trainer_thread.status_update.connect(self.update_status)
        self.trainer_thread.error_signal.connect(self.show_error)
        self.trainer_thread.success_signal.connect(self.show_success)
        self.trainer_thread.log_output.connect(self.append_console)
        self.trainer_thread.cheat_available.connect(self.set_cheat_available)
        self.trainer_thread.start()
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
    
    def stop_trainer(self):
        if self.trainer_thread:
            self.update_status("Stopping trainer...")
            self.trainer_thread.stop()
            self.trainer_thread = None
        
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.set_checkboxes_enabled(False)
        self.status_label.setStyleSheet("background-color: #8b0000; padding: 10px; border-radius: 5px;")
        self.update_status("Status: Disconnected")
        
        # Reset checkboxes
        self.no_reload_checkbox.setChecked(False)
        self.unlimited_fuel_checkbox.setChecked(False)
        
        # Clear console
        self.console_text.clear()
    
    def toggle_no_reload(self, state):
        if self.trainer_thread:
            self.trainer_thread.no_reload_enabled = (state == Qt.Checked)

    def toggle_unlimited_fuel(self, state):
        if self.trainer_thread:
            self.trainer_thread.unlimited_fuel_enabled = (state == Qt.Checked)
    
    def set_checkboxes_enabled(self, enabled):
        self.no_reload_checkbox.setEnabled(enabled)
        self.unlimited_fuel_checkbox.setEnabled(enabled)
    
    def set_cheat_available(self, cheat_name, is_available):
        """Enable or disable specific cheat checkbox based on address availability"""
        if cheat_name == "no_reload":
            self.no_reload_checkbox.setEnabled(is_available)
        elif cheat_name == "unlimited_fuel":
            self.unlimited_fuel_checkbox.setEnabled(is_available)
    
    def update_status(self, message):
        self.status_label.setText(f"Status: {message}")

    def show_success(self, message):
        self.status_label.setText(f"Success: {message}")
        self.status_label.setStyleSheet("background-color: #008000; padding: 10px; border-radius: 5px;")    
    
    def show_error(self, message):
        self.status_label.setText(f"Error: {message}")
        self.status_label.setStyleSheet("background-color: #8b0000; padding: 10px; border-radius: 5px;")
    
    def append_console(self, message):
        """Append a message to the console output"""
        self.console_text.append(message)
        # Auto-scroll to bottom
        self.console_text.verticalScrollBar().setValue(
            self.console_text.verticalScrollBar().maximum()
        )
    
    def closeEvent(self, event):
        if self.trainer_thread:
            self.stop_trainer()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = TrainerGUI()
    gui.show()
    sys.exit(app.exec_())

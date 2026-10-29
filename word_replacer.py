"""Example protected application: replaces a word in Word documents.

It exists to show the integration. The licensing part is four calls:
SecureLicenseManager(), status(), save_license(key), get_hardware_id().

Only .docx files whose name starts with "@@" are processed, so a wrong folder
cannot damage ordinary documents.
"""
from __future__ import annotations

import os
import sys
import traceback

from docx import Document
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication, QFileDialog, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPushButton, QTextEdit, QVBoxLayout, QWidget,
)

from security_system import SecureLicenseManager

FILE_PREFIX = "@@"


def hardware_id_box(manager: SecureLicenseManager) -> QTextEdit:
    box = QTextEdit(font=QFont("Consolas", 12), readOnly=True)
    box.setFixedHeight(50)
    box.setPlainText(manager.get_hardware_id())
    return box


class TechnicalDialog(QWidget):
    """License details and renewal."""

    def __init__(self, license_manager: SecureLicenseManager):
        super().__init__()
        self.license_manager = license_manager
        self.setWindowTitle("License")
        self.setFixedSize(420, 330)

        layout = QVBoxLayout()
        self.days_label = QLabel(font=QFont("Arial", 24), alignment=Qt.AlignCenter)
        layout.addWidget(self.days_label)
        self.expiry_label = QLabel(font=QFont("Arial", 10), alignment=Qt.AlignCenter)
        layout.addWidget(self.expiry_label)

        layout.addWidget(QLabel("Hardware ID (send it to the vendor to renew):", font=QFont("Arial", 10)))
        layout.addWidget(hardware_id_box(license_manager))

        layout.addWidget(QLabel("New license key:", font=QFont("Arial", 10)))
        self.key_input = QLineEdit(font=QFont("Consolas", 10))
        layout.addWidget(self.key_input)

        extend_btn = QPushButton("Extend License", font=QFont("Arial", 12))
        extend_btn.clicked.connect(self.extend_license)
        layout.addWidget(extend_btn)
        self.setLayout(layout)
        self.update_status()

    def update_status(self):
        status = self.license_manager.status()
        if status.valid:
            self.days_label.setText(f"{status.days_left} days left")
            self.expiry_label.setText(f"Expires on {status.expires.isoformat()}")
        else:
            self.days_label.setText("No valid license")
            self.expiry_label.setText(status.message)

    def extend_license(self):
        key = self.key_input.text().strip()
        if not key:
            QMessageBox.warning(self, "License", "Please enter a license key.")
            return
        ok, message = self.license_manager.save_license(key)
        if ok:
            self.key_input.clear()
            self.update_status()
            QMessageBox.information(self, "License", message)
        else:
            QMessageBox.critical(self, "License", message)


class ActivationDialog(QWidget):
    """Shown when there is no valid license."""

    finished = pyqtSignal(bool)   # True = activated

    def __init__(self, license_manager: SecureLicenseManager, reason: str):
        super().__init__()
        self.license_manager = license_manager
        self._activated = False
        self.setWindowTitle("Product Activation")
        self.setFixedSize(520, 300)

        layout = QVBoxLayout()
        layout.addWidget(QLabel(reason, font=QFont("Arial", 10), wordWrap=True))
        layout.addWidget(QLabel("Your Hardware ID (send it to the vendor):", font=QFont("Arial", 12)))
        layout.addWidget(hardware_id_box(license_manager))
        layout.addWidget(QLabel("License key:", font=QFont("Arial", 12)))
        self.key_input = QLineEdit(font=QFont("Consolas", 10))
        layout.addWidget(self.key_input)
        activate_btn = QPushButton("Activate", font=QFont("Arial", 12))
        activate_btn.clicked.connect(self.activate_license)
        layout.addWidget(activate_btn)
        self.setLayout(layout)

    def activate_license(self):
        key = self.key_input.text().strip()
        if not key:
            QMessageBox.warning(self, "Activation", "Please enter a license key.")
            return
        ok, message = self.license_manager.save_license(key)
        if ok:
            self._activated = True
            QMessageBox.information(self, "Activation", message)
            self.close()
        else:
            QMessageBox.critical(self, "Activation", message)

    def closeEvent(self, event):
        self.finished.emit(self._activated)
        super().closeEvent(event)


class WordReplacerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.license_manager = SecureLicenseManager()
        self.folder_path = ""
        self.init_ui()
        self.check_license()

    def init_ui(self):
        self.setWindowTitle("Word Replacer")
        self.setFixedSize(600, 400)
        font = QFont("Arial", 12)
        layout = QVBoxLayout()

        license_btn = QPushButton("License", font=font)
        license_btn.clicked.connect(self.show_technical)
        layout.addWidget(license_btn)

        browse_btn = QPushButton("Browse Folder", font=font)
        browse_btn.clicked.connect(self.browse_folder)
        layout.addWidget(browse_btn)
        self.folder_label = QLabel("No folder selected", font=QFont("Arial", 10))
        layout.addWidget(self.folder_label)

        layout.addWidget(QLabel("Word to find:", font=font))
        self.find_input = QLineEdit(font=font)
        layout.addWidget(self.find_input)
        layout.addWidget(QLabel("Replace with:", font=font))
        self.replace_input = QLineEdit(font=font)
        layout.addWidget(self.replace_input)

        self.start_btn = QPushButton("Start", font=font)
        self.start_btn.clicked.connect(self.start_replacement)
        layout.addWidget(self.start_btn)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    # ------------------------------------------------------------ license

    def check_license(self) -> bool:
        status = self.license_manager.status()
        self.start_btn.setEnabled(status.valid)
        if not status.valid:
            self.activation_dialog = ActivationDialog(self.license_manager, status.message)
            self.activation_dialog.finished.connect(lambda _activated: self.check_license_quietly())
            self.activation_dialog.show()
        return status.valid

    def check_license_quietly(self):
        self.start_btn.setEnabled(self.license_manager.status().valid)

    def show_technical(self):
        self.tech_dialog = TechnicalDialog(self.license_manager)
        self.tech_dialog.show()

    # ------------------------------------------------------------ work

    def browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            self.folder_path = folder
            self.folder_label.setText(folder)

    def start_replacement(self):
        if not self.check_license():
            return
        find, replace = self.find_input.text().strip(), self.replace_input.text().strip()
        if not self.folder_path or not find or not replace:
            QMessageBox.warning(self, "Word Replacer", "Select a folder and fill in both words.")
            return

        processed, errors = 0, []
        for root, _dirs, files in os.walk(self.folder_path):
            for name in files:
                if not (name.startswith(FILE_PREFIX) and name.lower().endswith(".docx")):
                    continue
                path = os.path.join(root, name)
                try:
                    doc = Document(path)
                    for paragraph in doc.paragraphs:
                        for run in paragraph.runs:
                            if find in run.text:
                                run.text = run.text.replace(find, replace)
                    doc.save(path)
                    processed += 1
                except Exception as exc:
                    errors.append(f"{name}: {exc}")

        if errors:
            QMessageBox.warning(self, "Word Replacer",
                                f"Processed {processed} file(s), {len(errors)} error(s):\n" + "\n".join(errors[:10]))
        elif processed:
            QMessageBox.information(self, "Word Replacer", f"Done: {processed} file(s) processed.")
        else:
            QMessageBox.warning(self, "Word Replacer",
                                f'No .docx files whose name starts with "{FILE_PREFIX}" were found.')


def main() -> int:
    def exception_hook(exc_type, value, tb):
        traceback.print_exception(exc_type, value, tb)
        QMessageBox.critical(None, "Unexpected error", f"{exc_type.__name__}: {value}")

    sys.excepthook = exception_hook
    app = QApplication(sys.argv)
    try:
        window = WordReplacerApp()
    except RuntimeError as exc:      # e.g. no public key configured
        QMessageBox.critical(None, "Word Replacer", str(exc))
        return 1
    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())

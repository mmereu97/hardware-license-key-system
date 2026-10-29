"""Vendor tool: signs license keys with the private key.

    python keygen.py

Needs vendor_private_key.pem (created by generate_keys.py). Never ship this
tool or the private key to customers.
"""
from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

from PyQt5.QtCore import QDate
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication, QCheckBox, QDateEdit, QHBoxLayout, QInputDialog, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QPushButton, QSpinBox, QTextEdit,
    QVBoxLayout, QWidget,
)

from license_core import MAX_DAYS, LicenseError, issue_license, load_private_key, read_license

PRIVATE_KEY_FILE = Path(__file__).resolve().parent / "vendor_private_key.pem"


def load_vendor_key(parent: QWidget):
    if not PRIVATE_KEY_FILE.exists():
        QMessageBox.critical(parent, "No private key",
                             f"{PRIVATE_KEY_FILE.name} not found.\nRun: python generate_keys.py")
        return None
    pem = PRIVATE_KEY_FILE.read_bytes()
    try:
        return load_private_key(pem)
    except TypeError:          # the key is encrypted: ask for the passphrase
        pass
    while True:
        passphrase, ok = QInputDialog.getText(parent, "Private key", "Passphrase:", QLineEdit.Password)
        if not ok:
            return None
        try:
            return load_private_key(pem, passphrase.encode())
        except (ValueError, TypeError):
            QMessageBox.warning(parent, "Private key", "Wrong passphrase.")


class KeyGeneratorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.private_key = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("License Key Generator (vendor)")
        self.resize(640, 520)
        font, mono = QFont("Arial", 11), QFont("Consolas", 11)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Customer's Hardware ID:", font=font))
        self.hwid_input = QLineEdit(font=mono)
        self.hwid_input.setPlaceholderText("1A2B3C4D-5E6F7A8B-9C0D1E2F-3A4B5C6D")
        layout.addWidget(self.hwid_input)

        row = QHBoxLayout()
        row.addWidget(QLabel("Days:", font=font))
        self.days_input = QSpinBox(font=font)
        self.days_input.setRange(1, MAX_DAYS)
        self.days_input.setValue(30)
        row.addWidget(self.days_input)
        row.addStretch()
        layout.addLayout(row)

        row = QHBoxLayout()
        self.extend_check = QCheckBox("Extend from the current expiry date:", font=font)
        self.extend_date = QDateEdit(QDate.currentDate(), font=font)
        self.extend_date.setCalendarPopup(True)
        self.extend_date.setDisplayFormat("yyyy-MM-dd")
        self.extend_date.setEnabled(False)
        self.extend_check.toggled.connect(self.extend_date.setEnabled)
        row.addWidget(self.extend_check)
        row.addWidget(self.extend_date)
        row.addStretch()
        layout.addLayout(row)

        generate_btn = QPushButton("Generate License Key", font=font)
        generate_btn.clicked.connect(self.generate_key)
        layout.addWidget(generate_btn)

        layout.addWidget(QLabel("License key (send this to the customer):", font=font))
        self.key_output = QTextEdit(font=mono, readOnly=True)
        self.key_output.setFixedHeight(90)
        layout.addWidget(self.key_output)

        copy_btn = QPushButton("Copy key", font=font)
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.key_output.toPlainText()))
        layout.addWidget(copy_btn)

        self.key_info = QTextEdit(font=font, readOnly=True)
        self.key_info.setFixedHeight(110)
        layout.addWidget(self.key_info)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def generate_key(self):
        if self.private_key is None:
            self.private_key = load_vendor_key(self)
            if self.private_key is None:
                return
        start = None
        if self.extend_check.isChecked():
            start = self.extend_date.date().toPyDate()
        try:
            key = issue_license(self.private_key, self.hwid_input.text(), self.days_input.value(), start=start)
        except LicenseError as exc:
            QMessageBox.warning(self, "Cannot generate", str(exc))
            return

        lic = read_license(key, self.private_key.public_key())
        self.key_output.setPlainText(key)
        self.key_info.setPlainText(
            f"Hardware ID:  {lic.hardware_id}\n"
            f"Issued on:    {lic.issued.isoformat()}\n"
            f"Expires on:   {lic.expires.isoformat()}  ({lic.days_left(date.today())} days from today)\n"
            f"License ID:   {lic.license_id}"
        )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = KeyGeneratorApp()
    window.show()
    sys.exit(app.exec_())

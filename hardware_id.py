"""Reads the hardware components that identify this computer.

Windows: WMI (CPU, BIOS, motherboard, system disk).
Other systems: a best-effort fallback (machine-id, CPU), so the demo and the
tests also run on Linux/macOS.

Deliberately NOT used, because they change without the computer changing:
MAC address (VPNs, docks, Wi-Fi vs. cable), Windows build number (updates),
computer name (renaming), BIOS version (firmware updates).
"""
from __future__ import annotations

import platform
import sys
import uuid
from pathlib import Path
from typing import Dict

from license_core import COMPONENTS, format_hardware_id, is_placeholder


def _join(*values) -> str:
    return ":".join(str(v).strip() for v in values if not is_placeholder(None if v is None else str(v)))


def _identified_by(serial, *details) -> str:
    """A component counts only if its serial number is real: model names alone
    are shared by thousands of machines. Placeholders ("To be filled by O.E.M.")
    make the whole component unreadable."""
    if serial is None or is_placeholder(str(serial)):
        return ""
    return _join(*details, serial)


def _windows_components() -> Dict[str, str]:
    import wmi  # Windows only

    client = wmi.WMI()
    result = {name: "" for name in COMPONENTS}
    try:
        cpu = client.Win32_Processor()[0]
        result["cpu"] = _join(cpu.ProcessorId, cpu.Name)
    except Exception:
        pass
    try:
        bios = client.Win32_BIOS()[0]
        result["bios"] = _identified_by(bios.SerialNumber, bios.Manufacturer)
    except Exception:
        pass
    try:
        board = client.Win32_BaseBoard()[0]
        result["board"] = _identified_by(board.SerialNumber, board.Manufacturer, board.Product)
    except Exception:
        pass
    try:
        disk = next((d for d in client.Win32_DiskDrive() if d.Index == 0), None)
        if disk is not None:
            result["disk"] = _identified_by(disk.SerialNumber, disk.Model)
    except Exception:
        pass
    return result


def _fallback_components() -> Dict[str, str]:
    machine_id = ""
    for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            machine_id = Path(candidate).read_text().strip()
            if machine_id:
                break
        except OSError:
            continue
    return {
        "cpu": _join(platform.machine(), platform.processor()),
        "bios": "",
        "board": machine_id or f"{uuid.getnode():012x}",
        "disk": "",
    }


def collect_components() -> Dict[str, str]:
    """Raw component strings for this computer (never raises)."""
    if sys.platform == "win32":
        try:
            return _windows_components()
        except Exception:
            pass
    return _fallback_components()


def current_hardware_id() -> str:
    return format_hardware_id(collect_components())

#!/usr/bin/env python3
"""Carv forensic recovery workstation GUI.

Coordinates guarded source selection, recovery execution, live monitoring and
durable completion reporting. Source discovery and source reading remain
separate, explicit operations.
"""

from __future__ import annotations

import codecs
import configparser
import csv
from dataclasses import dataclass, field
from datetime import datetime
import fcntl
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import shlex
import shutil
import struct
import subprocess
import sys
import threading
import time
import traceback
from urllib.parse import quote, unquote

MFT_RECORD_SIZE = 1024
MFTPROBE_BIN_MAGIC_V1 = b"C26MFT1"
MFTPROBE_BIN_MAGIC_V2 = b"C26MFT2"
MFTPROBE_BIN_MAGIC_V3 = b"C26MFT3"
MFTPROBE_LEGACY_RECORD_MAGIC = b"MFR1"
MFTPROBE_BIN_ROW_SIZE_V1 = 104
MFTPROBE_BIN_ROW_SIZE_V2 = 144
MFTPROBE_BIN_ROW_SIZE_V3 = 152
MFTPROBE_LEGACY_MAP_HEADER_SIZE = 44
MFTPROBE_LEGACY_MAP_RECORD_FIXED_SIZE = 120
MFT_INTERNAL_COMPONENT_NAMES = {
    "$mft", "$mftmirr", "$logfile", "$volume", "$attrdef", "$bitmap",
    "$boot", "$badclus", "$secure", "$upcase", "$extend",
}


def encode_folder_scope_paths(paths: list[str]) -> str:
    """Encode UTF-8 scope items without confusing filename commas with separators."""
    return "@scope-v1:" + ",".join(quote(path, safe="/-_.~") for path in paths)


def decode_folder_scope_paths(value: str) -> list[str]:
    """Decode Carv's versioned folder-scope list for operator reporting."""
    text = str(value or "").strip()
    if not text:
        return []
    if text.startswith("@scope-v1:"):
        payload = text[len("@scope-v1:"):]
        return [unquote(item) for item in payload.split(",") if item]
    return [item.strip() for item in text.split(",") if item.strip()]


def normalize_hypersafe_priority_terms(text: str) -> list[str]:
    """Return distinct folder-name fragments entered one per line.

    Matching is implicitly "contains", so surrounding ? or * characters are
    accepted as operator-friendly notation but are not sent as literal NTFS
    filename characters.
    """
    terms = []
    seen = set()
    for raw_line in str(text or "").splitlines():
        term = raw_line.strip()
        while term and term[0] in "?*":
            term = term[1:].lstrip()
        while term and term[-1] in "?*":
            term = term[:-1].rstrip()
        if not term:
            continue
        folded = term.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        terms.append(term)
    return terms


try:
    from PyQt6.QtCore import QEvent, Qt, QTimer
    from PyQt6.QtGui import QBrush, QColor, QFont, QFontDatabase, QIcon, QPainter, QPen, QPixmap, QTextOption
    from PyQt6.QtWidgets import (
        QApplication,
        QAbstractItemView,
        QCheckBox,
        QComboBox,
        QDialog,
        QDialogButtonBox,
        QFrame,
        QFileDialog,
        QGraphicsDropShadowEffect,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QInputDialog,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QPlainTextEdit,
        QProgressBar,
        QRadioButton,
        QScrollArea,
        QSlider,
        QSplitter,
        QTabWidget,
        QTabBar,
        QTreeWidget,
        QTreeWidgetItem,
        QToolTip,
        QVBoxLayout,
        QWidget,
    )
    QT_LIB = "PyQt6"
except ImportError:
    try:
        from PySide6.QtCore import QEvent, Qt, QTimer
        from PySide6.QtGui import QBrush, QColor, QFont, QFontDatabase, QIcon, QPainter, QPen, QPixmap, QTextOption
        from PySide6.QtWidgets import (
            QApplication,
            QAbstractItemView,
            QCheckBox,
            QComboBox,
            QDialog,
            QDialogButtonBox,
            QFrame,
            QFileDialog,
            QGraphicsDropShadowEffect,
            QGridLayout,
            QGroupBox,
            QHBoxLayout,
            QInputDialog,
            QLabel,
            QLineEdit,
            QMainWindow,
            QMessageBox,
            QPushButton,
            QPlainTextEdit,
            QProgressBar,
            QRadioButton,
            QScrollArea,
            QSlider,
            QSplitter,
            QTabWidget,
            QTabBar,
            QTreeWidget,
            QTreeWidgetItem,
            QToolTip,
            QVBoxLayout,
            QWidget,
        )
        QT_LIB = "PySide6"
    except ImportError:
        print("Install PyQt6 or PySide6 to run the Carv GUI.", file=sys.stderr)
        raise SystemExit(1)


BG = "#101317"
PANEL = "#181d22"
SUBTLE = "#222930"
TEXT = "#e6edf1"
MUTED = "#7e8b96"
ACCENT = "#08d67b"
BORDER = "#35404a"
WARNING = "#d6a84f"


def guarded_qt_timer(callback, label: str):
    """Keep Python exceptions from crossing PyQt6's fatal timer boundary."""
    def guarded(*args, **kwargs):
        try:
            return callback(*args, **kwargs)
        except Exception:
            print(
                f"[GUI ERROR] Timer '{label}' failed:\n{traceback.format_exc()}",
                file=sys.stderr,
                flush=True,
            )
            return None

    return guarded
TAB_ACTIVE = "#1c2329"
TAB_INACTIVE = "#14191e"
START_TOP = "#959ea6"
START_BOTTOM = "#535b63"
STEEL_TOP = "#232b32"
STEEL_MID = "#1b2228"
STEEL_LOW = "#151a1f"
STEEL_EDGE = "#35414b"
STEEL_DARK = "#697784"
GUI_CONFIG_SECTION = "gui"
GUI_CONFIG_DEFAULT_OUT_KEY = "default_out"
GUI_CONFIG_RECENT_SERVICE_IDS_KEY = "recent_service_ids"
SOURCE_DEVICE_SEEN_FILENAME = "carv_source_devices_seen.json"
SOURCE_TREE_CACHE_FILENAME = "carv_source_tree_cache.json"
HYPERSAFE_UI_VISIBLE = True
WAIT_FOR_NEW_SOURCE_TOKEN = "__CARV_WAIT_FOR_NEW_SOURCE__"
ANSI_ESCAPE_RE = re.compile(
    r"\x1b(?:"
    r"\[[0-?]*[ -/]*[@-~]"
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|[@-_]"
    r")"
)
TERMINAL_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
DDRESCUE_PROGRESS_LINE_RE = re.compile(
    r"^\s*(?:"
    r"ipos:|opos:|non-tried:|non-trimmed:|non-scraped:|"
    r"rescued:|pct rescued:|time since last successful read:|"
    r"Copying .*blocks|Retrying .*blocks|Trimming .*blocks|Scraping .*blocks"
    r")",
    re.IGNORECASE,
)
DDRESCUE_PROGRESS_EVENT_PREFIX = "[[CARV_DDRESCUE_PROGRESS]]"


def app_runtime_root() -> Path:
    bundled_root = getattr(sys, "_MEIPASS", None)
    if bundled_root:
        return Path(str(bundled_root)).resolve()
    return Path(__file__).resolve().parents[1]


def app_version() -> str:
    version_path = app_runtime_root() / "VERSION"
    try:
        version = version_path.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version):
            return version
    except OSError:
        pass

    # Development runs use the version directly from the project Makefile.
    try:
        makefile = (app_runtime_root() / "Makefile").read_text(encoding="utf-8")
        match = re.search(r"^CARV_VERSION\s*\?=\s*([^\s#]+)", makefile, re.MULTILINE)
        if match:
            return match.group(1)
    except OSError:
        pass
    return "development"


CARV_VERSION = app_version()
WRENCH_ICON_PATH = str(app_runtime_root() / "scripts" / "wrench_button_icon.png")
CARV_TITLE_LOGO_PATH = str(app_runtime_root() / "scripts" / "carv_title_logo.png")


def legacy_app_config_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "carv_ui.ini"
    return app_runtime_root() / "carv_ui.ini"


def app_config_path() -> Path:
    override = os.environ.get("CARV_CONFIG_HOME", "").strip()
    if override:
        return Path(override).expanduser() / "carv_ui.ini"
    config_home = Path(
        os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    ).expanduser()
    return config_home / "carv" / "carv_ui.ini"


def sudo_askpass_environment(title: str, prompt: str, ok_text: str, base=None) -> tuple[dict, str]:
    helper = app_runtime_root() / "scripts" / "carv_gui_askpass.py"
    if not helper.exists():
        return {}, f"Password helper is missing: {helper}"
    environment = dict(os.environ if base is None else base)
    environment.update({
        "SUDO_ASKPASS": str(helper),
        "CARV_ASKPASS_TITLE": str(title or "Carv needs permission"),
        "CARV_ASKPASS_PROMPT": str(prompt or "Carv needs sudo permission."),
        "CARV_ASKPASS_OK": str(ok_text or "Continue"),
        "CARV_ASKPASS_CANCEL": "Cancel",
    })
    return environment, ""


def ensure_sudo_credential(
    title: str,
    prompt: str,
    ok_text: str,
    *,
    cwd: str | None = None,
    noninteractive: bool = False,
) -> tuple[bool, dict, str]:
    if noninteractive:
        environment = os.environ.copy()
        command = ["sudo", "-n", "-v"]
    else:
        environment, error = sudo_askpass_environment(title, prompt, ok_text)
        if error:
            return False, {}, error
        command = ["sudo", "-A", "-v"]
    try:
        result = subprocess.run(
            command,
            cwd=cwd or str(app_runtime_root()),
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, environment, f"Could not run sudo: {exc}"
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "sudo authentication failed").strip()
        return False, environment, detail
    return True, environment, ""


def sudo_auth_failed_text(text: str) -> bool:
    lowered = str(text or "").casefold()
    return any(
        needle in lowered
        for needle in (
            "a password is required",
            "password is required",
            "sudo needed",
            "sudo: a password",
            "sudo: no tty",
            "try again",
        )
    )


def expire_sudo_credential(cwd: str | None = None) -> None:
    try:
        subprocess.run(
            ["sudo", "-k"],
            cwd=cwd or str(app_runtime_root()),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        pass


@lru_cache(maxsize=1)
def mono_font_family() -> str:
    """Return the platform's installed fixed-width UI font."""
    families = set(QFontDatabase.families())
    for family in ("Menlo", "SF Mono", "DejaVu Sans Mono", "Liberation Mono", "Courier New"):
        if family in families:
            return family
    return sorted(families)[0] if families else "Courier"


@lru_cache(maxsize=1)
def ui_font_family() -> str:
    """Return the platform's installed general UI font."""
    families = set(QFontDatabase.families())
    for family in ("Helvetica Neue", "Helvetica", "Noto Sans", "DejaVu Sans", "Liberation Sans", "Arial"):
        if family in families:
            return family
    return sorted(families)[0] if families else "Arial"


class TechnicalComboBox(QComboBox):
    """Cross-platform combobox with a consistent workshop-style chevron."""

    def __init__(self, editable: bool = False, parent=None) -> None:
        super().__init__(parent)
        self.setEditable(editable)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(
            f"""
            QComboBox {{
                background-color: {SUBTLE};
                color: {TEXT};
                border: 1px solid {BORDER};
                border-radius: 4px;
                padding: 8px 32px 8px 8px;
            }}
            QComboBox:editable {{ background-color: {SUBTLE}; }}
            QComboBox::drop-down {{
                background-color: {SUBTLE};
                border: none;
                border-left: 1px solid {BORDER};
                width: 26px;
            }}
            QComboBox::down-arrow {{ image: none; }}
            QComboBox QAbstractItemView {{
                background-color: {SUBTLE};
                color: {TEXT};
                border: 1px solid {BORDER};
                selection-background-color: #1d4937;
            }}
            """
        )
        if self.lineEdit() is not None:
            self.lineEdit().setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
            self.lineEdit().setStyleSheet(
                f"background-color: {SUBTLE}; color: {TEXT}; border: none; padding: 0;"
            )

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        pen = QPen(QColor(MUTED))
        pen.setWidthF(1.4)
        painter.setPen(pen)
        center_x = self.width() - 13
        center_y = self.height() // 2
        painter.drawLine(center_x - 4, center_y - 2, center_x, center_y + 2)
        painter.drawLine(center_x, center_y + 2, center_x + 4, center_y - 2)
        painter.end()


def group_box(title: str) -> QGroupBox:
    box = QGroupBox(title)
    box.setStyleSheet(
        f"""
        QGroupBox {{
            background: {PANEL};
            border: 1px solid {BORDER};
            border-radius: 6px;
            margin-top: 10px;
            font-family: "{mono_font_family()}";
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1.1px;
            color: {MUTED};
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 12px;
            background: {PANEL};
            border: 1px solid {BORDER};
            border-bottom: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            padding: 4px 8px 3px;
        }}
        """
    )
    return box


def labeled_field(label: str, widget: QWidget) -> QWidget:
    container = QWidget()
    layout = QVBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(4)

    text = QLabel(label)
    text.setStyleSheet(
        f"color: {MUTED}; font-family: '{mono_font_family()}'; "
        "font-size: 10px; font-weight: 700; letter-spacing: 0.8px;"
    )
    layout.addWidget(text)
    layout.addWidget(widget)
    return container


def labeled_slider(label: str, value_text: str, slider: QSlider) -> QWidget:
    container = QWidget()
    layout = QVBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(4)

    row = QHBoxLayout()
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(8)

    text = QLabel(label)
    text.setStyleSheet(
        f"color: {MUTED}; font-family: '{mono_font_family()}'; "
        "font-size: 10px; font-weight: 700; letter-spacing: 0.8px;"
    )
    value = QLabel(value_text)
    value.setStyleSheet(f"color: {ACCENT}; font-family: '{mono_font_family()}'; font-size: 11px;")
    row.addWidget(text)
    row.addStretch(1)
    row.addWidget(value)

    layout.addLayout(row)
    layout.addWidget(slider)
    container.value_label = value
    return container


class HighlightTabBar(QTabBar):
    """Tab bar that can outline one attention-requiring tab."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._highlighted_index = -1

    def set_highlighted_index(self, index: int) -> None:
        self._highlighted_index = index
        self.update()

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if self._highlighted_index < 0 or self._highlighted_index >= self.count():
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(QColor(ACCENT))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        rect = self.tabRect(self._highlighted_index).adjusted(0, 0, -1, -1)
        painter.drawRoundedRect(rect, 4, 4)
        painter.end()


@dataclass(frozen=True)
class DiskMapSegment:
    start_offset: int
    end_offset: int
    geometry: str = "span"
    kind: str = ""
    confidence: str = "exact"
    source: str = ""
    label: str = ""
    count: int = 1

    @property
    def byte_length(self) -> int:
        return max(0, int(self.end_offset) - int(self.start_offset))


@dataclass
class DiskMapSnapshot:
    source_size: int = 0
    view_start_offset: int = 0
    view_end_offset: int = 0
    scope: list[DiskMapSegment] = field(default_factory=list)
    read: list[DiskMapSegment] = field(default_factory=list)
    recovered: list[DiskMapSegment] = field(default_factory=list)
    errors: list[DiskMapSegment] = field(default_factory=list)
    skipped: list[DiskMapSegment] = field(default_factory=list)
    recovered_outputs: int = 0
    positioned_outputs: int = 0
    recovered_count_is_files: bool = False
    notes: list[str] = field(default_factory=list)


class CumulativeEvidenceWidget(QWidget):
    """One physical source bar with file findings layered by priority."""

    DENSE_RECOVERY_THRESHOLD = 12
    DENSE_RECOVERY_COLOR = ACCENT

    LAYERS = (
        ("read", "Read", "#6f9abf"),
        ("skipped", "Skipped range", "#e6a23c"),
        ("recovered", "Recovered", "#9cff00"),
        # Physical read errors are painted last so a narrow red problem mark
        # remains visible over read/recovery coverage at the same coordinate.
        ("errors", "Read error", "#ff315c"),
    )

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._snapshot = DiskMapSnapshot()
        self._hover_tooltip = ""
        self.setMouseTracking(True)
        self.setFixedHeight(52)

    def clear(self) -> None:
        self.set_snapshot(DiskMapSnapshot())

    def set_snapshot(self, snapshot: DiskMapSnapshot) -> None:
        self._snapshot = snapshot if isinstance(snapshot, DiskMapSnapshot) else DiskMapSnapshot()
        self._hover_tooltip = ""
        self.update()

    def _layout(self):
        margin = 5
        bar_top = margin
        bar_height = 25
        bar_left = margin
        bar_width = max(32, self.width() - (margin * 2))
        axis_top = bar_top + bar_height + 3
        return bar_top, bar_height, bar_left, bar_width, axis_top

    def _coordinate_bounds(self) -> tuple[int, int]:
        source_size = max(0, int(self._snapshot.source_size or 0))
        view_start = max(0, int(self._snapshot.view_start_offset or 0))
        view_end = max(view_start, int(self._snapshot.view_end_offset or 0))
        if view_end > view_start:
            if source_size > 0:
                view_start = min(view_start, source_size)
                view_end = min(view_end, source_size)
            if view_end > view_start:
                return view_start, view_end
        return 0, source_size

    def _segment_rect(self, segment: DiskMapSegment, top: int, height: int, left: int, width: int):
        view_start, view_end = self._coordinate_bounds()
        view_size = max(1, view_end - view_start)
        inner_width = max(1, width - 2)
        start = max(view_start, min(view_end, int(segment.start_offset)))
        end = max(start, min(view_end, int(segment.end_offset)))
        center = left + 1 + round(((start - view_start) / view_size) * inner_width)
        if segment.geometry == "point" or end <= start:
            segment_left = max(left + 1, min(left + inner_width - 2, center - 1))
            return segment_left, top + 1, 3, max(1, height - 2)
        segment_left = left + 1 + int(((start - view_start) / view_size) * inner_width)
        segment_right = left + 1 + int((((end - view_start) / view_size) * inner_width) + 0.999999)
        segment_width = max(2, segment_right - segment_left)
        segment_width = min(segment_width, max(1, left + width - 1 - segment_left))
        return segment_left, top + 1, segment_width, max(1, height - 2)

    @staticmethod
    def _format_map_bytes(value: int) -> str:
        units = ("B", "KiB", "MiB", "GiB", "TiB")
        amount = float(max(0, int(value)))
        unit = units[0]
        for unit in units:
            if amount < 1024.0 or unit == units[-1]:
                break
            amount /= 1024.0
        return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.2f} {unit}"

    def _segment_tooltip(self, lane_label: str, segment: DiskMapSegment) -> str:
        view_start, view_end = self._coordinate_bounds()
        view_size = max(1, view_end - view_start)
        start_percent = ((segment.start_offset - view_start) / view_size) * 100.0
        if segment.geometry == "point" or segment.end_offset <= segment.start_offset:
            extent_lines = [
                f"Position {segment.start_offset:,} B · {start_percent:.4f}%",
            ]
        else:
            end_percent = ((segment.end_offset - view_start) / view_size) * 100.0
            extent_lines = [
                f"Start {segment.start_offset:,} B · {start_percent:.4f}%",
                f"End   {segment.end_offset:,} B · {end_percent:.4f}%",
                f"Length {self._format_map_bytes(segment.byte_length)} · {segment.byte_length:,} B",
            ]
        details = [lane_label]
        if segment.label:
            details.append(segment.label)
        details.extend(extent_lines)
        facts = [value for value in (segment.kind, segment.confidence, segment.source) if value]
        if facts:
            details.append(" · ".join(facts))
        if segment.count > 1:
            details.append(f"{segment.count:,} observations")
        return "\n".join(details)

    def _screen_segment_groups(self, segments, top: int, height: int, left: int, width: int):
        rendered = []
        for segment in segments:
            rect = self._segment_rect(segment, top, height, left, width)
            rendered.append((rect[0], rect[0] + rect[2], rect, segment))
        rendered.sort(key=lambda item: (item[0], item[1]))
        groups = []
        for segment_left, segment_right, rect, segment in rendered:
            if groups and segment_left <= groups[-1]["right"] + 2:
                group = groups[-1]
                group["right"] = max(group["right"], segment_right)
                group["segments"].append(segment)
            else:
                groups.append({
                    "left": segment_left,
                    "right": segment_right,
                    "rect": rect,
                    "segments": [segment],
                })
        return groups

    @staticmethod
    def _group_observation_count(group) -> int:
        labels = {segment.label for segment in group["segments"] if segment.label}
        if labels:
            return len(labels)
        return sum(max(1, int(segment.count or 1)) for segment in group["segments"])

    def _group_is_dense(self, group) -> bool:
        return self._group_observation_count(group) >= self.DENSE_RECOVERY_THRESHOLD

    def _group_tooltip(self, layer_label: str, group) -> str:
        segments = group["segments"]
        count = self._group_observation_count(group)
        if len(segments) == 1 and count == 1:
            return self._segment_tooltip(layer_label, segments[0])
        effective_label = "Dense recover" if self._group_is_dense(group) else layer_label
        lines = [effective_label, f"{count:,} recovered files/extents share this screen position"]
        for segment in segments[:8]:
            label = segment.label or segment.kind or "Evidence"
            if segment.geometry == "point" or segment.end_offset <= segment.start_offset:
                extent = f"{segment.start_offset:,} B"
            else:
                extent = (
                    f"{segment.start_offset:,}–{segment.end_offset:,} B "
                    f"({self._format_map_bytes(segment.byte_length)})"
                )
            lines.append(f"• {label}: {extent}")
        if len(segments) > 8:
            lines.append(f"…and {len(segments) - 8:,} more extents")
        return "\n".join(lines)

    def _tooltip_for_position(self, x_pos: int, y_pos: int) -> str:
        view_start, view_end = self._coordinate_bounds()
        if view_end <= view_start:
            return "Waiting for file findings"
        top, height, left, width, _axis_top = self._layout()
        if x_pos < left or x_pos >= left + width:
            return ""
        ratio = max(0.0, min(1.0, (x_pos - left - 1) / float(max(1, width - 2))))
        position = view_start + round(ratio * (view_end - view_start))
        lines = [f"Disk position {self._format_map_bytes(position)} · {ratio * 100:.2f}% of displayed scope"]
        hit_details = []
        for key, layer_label, _color in reversed(self.LAYERS):
            segments = getattr(self._snapshot, key, [])
            if key == "recovered":
                for group in self._screen_segment_groups(segments, top, height, left, width):
                    if group["left"] <= x_pos < group["right"]:
                        hit_details.append(self._group_tooltip(layer_label, group))
                        break
                continue
            for segment in reversed(segments):
                seg_left, _seg_top, seg_width, _seg_height = self._segment_rect(
                    segment, top, height, left, width
                )
                if seg_left <= x_pos < seg_left + seg_width:
                    hit_details.append(self._segment_tooltip(layer_label, segment))
                    break
        if hit_details:
            lines.extend(hit_details)
        else:
            lines.append("No recorded read coverage at this position")
        return "\n\n".join(lines)

    def mouseMoveEvent(self, event) -> None:
        if hasattr(event, "position"):
            position = event.position()
            global_position = event.globalPosition().toPoint()
        else:
            position = event.pos()
            global_position = event.globalPos()
        tooltip = self._tooltip_for_position(int(position.x()), int(position.y()))
        if tooltip != self._hover_tooltip:
            self._hover_tooltip = tooltip
            if tooltip:
                QToolTip.showText(global_position, tooltip, self)
            else:
                QToolTip.hideText()
        super().mouseMoveEvent(event)

    def leaveEvent(self, event) -> None:
        self._hover_tooltip = ""
        QToolTip.hideText()
        super().leaveEvent(event)

    def _draw_skipped_segment(self, painter, rect, color: QColor) -> None:
        x, y, width, height = rect
        fill = QColor(color)
        fill.setAlpha(92)
        painter.fillRect(x, y, width, height, fill)
        painter.save()
        painter.setClipRect(x, y, width, height)
        painter.setPen(QPen(color, 1))
        for stripe_x in range(x - height, x + width + height, 6):
            painter.drawLine(stripe_x, y + height, stripe_x + height, y)
        painter.restore()

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        top, height, left, width, axis_top = self._layout()
        view_start, view_end = self._coordinate_bounds()
        view_size = max(0, view_end - view_start)
        painter.fillRect(left, top, width, height, QColor(SUBTLE))

        if view_size > 0:
            # One source, one coordinate system. Later layers have higher
            # visual priority but never change the underlying disk position.
            for key, _label, color_text in self.LAYERS:
                color = QColor(color_text)
                if key == "recovered":
                    for group in self._screen_segment_groups(
                        getattr(self._snapshot, key, []), top, height, left, width
                    ):
                        recovered_color = QColor(
                            self.DENSE_RECOVERY_COLOR if self._group_is_dense(group) else color_text
                        )
                        marker_width = max(3, group["right"] - group["left"])
                        painter.fillRect(
                            group["left"], top + 1, marker_width, max(1, height - 2), recovered_color
                        )
                    continue
                for segment in getattr(self._snapshot, key, []):
                    rect = self._segment_rect(segment, top, height, left, width)
                    if key == "skipped":
                        self._draw_skipped_segment(painter, rect, color)
                    else:
                        painter.fillRect(*rect, color)

            # Percentage ticks sit below the evidence rather than cutting
            # through thin recovery/error marks.
            for percent in (0, 25, 50, 75, 100):
                x_pos = left + round((percent / 100.0) * max(1, width - 1))
                painter.setPen(QPen(QColor("#34414b"), 1))
                painter.drawLine(x_pos, top + height, x_pos, axis_top + 2)
                text_width = 34
                text_left = max(left, min(left + width - text_width, x_pos - text_width // 2))
                painter.setPen(QColor(MUTED))
                painter.drawText(text_left, axis_top, text_width, 15, Qt.AlignmentFlag.AlignHCenter, f"{percent}%")
        else:
            painter.setPen(QColor(MUTED))
            painter.drawText(
                left, top, width, height,
                Qt.AlignmentFlag.AlignCenter,
                "Waiting for file findings…",
            )
        painter.setPen(QPen(QColor(BORDER)))
        painter.drawRect(left, top, max(0, width - 1), max(0, height - 1))
        painter.end()

class StartRecoveryButton(QPushButton):
    def __init__(self) -> None:
        super().__init__("EXECUTE RECOVERY")
        self.setObjectName("startRecoveryButton")
        self._icon = QPixmap(WRENCH_ICON_PATH)
        self.setStyleSheet(
            """
            QPushButton {
                color: #111609;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 1px;
                padding: 10px 34px 10px 16px;
                border-radius: 4px;
                border: 1px solid #08a960;
                background: #078e51;
            }
            QPushButton:hover {
                border: 1px solid #08d67b;
                background: #08a960;
            }
            QPushButton:pressed {
                padding-top: 9px;
                padding-bottom: 7px;
                background: #057140;
            }
            QPushButton:disabled {
                color: #58655f;
                background: #17201c;
                border: 1px solid #304038;
            }
            """
        )

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if self._icon.isNull():
            return

        icon = self._icon.scaled(
            14,
            14,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        monochrome = QPixmap(icon.size())
        monochrome.fill(Qt.GlobalColor.transparent)
        icon_painter = QPainter(monochrome)
        icon_painter.drawPixmap(0, 0, icon)
        icon_painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
        icon_color = "#07140d" if self.isEnabled() else "#46534d"
        icon_painter.fillRect(monochrome.rect(), QColor(icon_color))
        icon_painter.end()

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.drawPixmap(self.width() - 24, (self.height() - monochrome.height()) // 2, monochrome)
        painter.end()


class ToggleSwitch(QCheckBox):
    """A compact, keyboard-accessible on/off switch for workstation controls."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setText("")
        self.setFixedSize(34, 18)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTipDuration(8000)

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        track = self.rect().adjusted(0, 2, 0, -2)
        active = self.isChecked()
        if not self.isEnabled():
            track_color, knob_color, edge_color = "#283139", "#58636d", "#35404a"
        elif active:
            track_color, knob_color, edge_color = "#078e51", "#d8ffe9", ACCENT
        else:
            track_color, knob_color, edge_color = "#28323a", "#9aa7b0", "#52606b"
        painter.setPen(QPen(QColor(edge_color), 1))
        painter.setBrush(QColor(track_color))
        painter.drawRoundedRect(track, track.height() / 2, track.height() / 2)
        knob_size = max(8, track.height() - 4)
        knob_x = track.right() - knob_size - 2 if active else track.left() + 2
        knob_y = track.top() + (track.height() - knob_size) // 2
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(knob_color))
        painter.drawEllipse(knob_x, knob_y, knob_size, knob_size)
        painter.end()


class SourcePickerDialog(QDialog):
    """Source picker that performs device discovery only after explicit consent."""

    def __init__(self, parent=None, *, allow_wait_for_source: bool = False) -> None:
        super().__init__(parent)
        self.setWindowTitle("Choose Source")
        self.resize(980, 560)
        self.setStyleSheet(
            f"""
            QDialog {{ background: {BG}; }}
            QLabel {{ color: {TEXT}; background: transparent; }}
            QTreeWidget {{
                background: #14191e;
                alternate-background-color: #171d22;
                color: {TEXT};
                border: 1px solid {BORDER};
                border-radius: 4px;
                outline: none;
                font-family: "{ui_font_family()}";
                font-size: 12px;
                selection-background-color: #1d4937;
                selection-color: {TEXT};
            }}
            QTreeWidget::item {{ height: 27px; padding: 0 5px; border: none; }}
            QTreeWidget::item:selected {{
                background: #1d4937;
                color: {TEXT};
                border-left: 2px solid {ACCENT};
            }}
            QTreeWidget::item:hover {{ background: #1b252b; }}
            QTreeWidget::item:selected:hover {{
                background: #24533f;
                color: {TEXT};
                border-left: 2px solid {ACCENT};
            }}
            QHeaderView::section {{
                background: #101519;
                color: {MUTED};
                border: none;
                border-bottom: 1px solid {BORDER};
                padding: 7px 8px;
                font-family: "{mono_font_family()}";
                font-size: 10px;
                font-weight: 700;
            }}
            QPushButton {{
                background: {SUBTLE};
                border: 1px solid {BORDER};
                color: {TEXT};
                border-radius: 4px;
                padding: 7px 12px;
                font-family: "{ui_font_family()}";
            }}
            QPushButton:hover {{ border-color: {ACCENT}; background: #273139; }}
            QPushButton:pressed {{ background: #182027; }}
            QPushButton:disabled {{
                background: #171c21;
                border-color: #2b343c;
                color: #58636d;
            }}
            QPushButton#readSourceButton {{
                background: #17231e;
                border: 1px solid #287d58;
                color: {ACCENT};
                font-family: "{mono_font_family()}";
                font-size: 10px;
                font-weight: 700;
                padding: 9px 14px;
            }}
            QPushButton#dialogPrimary {{
                min-width: 168px;
                color: {ACCENT};
                background: #17231e;
                border: 1px solid #08a960;
                font-weight: 700;
                padding: 9px 14px;
            }}
            QPushButton#dialogPrimary:hover {{
                color: #44e69b;
                background: #1d3328;
                border-color: {ACCENT};
            }}
            QPushButton#dialogPrimary:disabled {{
                background: #17201c;
                border-color: #304038;
                color: #58655f;
            }}
            QDialogButtonBox {{ background: transparent; }}
            QDialogButtonBox QPushButton {{ min-width: 112px; padding: 9px 14px; }}
            QCheckBox {{ color: {TEXT}; background: transparent; }}
            QCheckBox::indicator {{
                width: 13px; height: 13px; border: 1px solid {STEEL_DARK};
                border-radius: 2px; background: {SUBTLE};
            }}
            QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}
            QScrollBar:vertical {{
                background: #101519;
                width: 10px;
                margin: 0;
            }}
            QScrollBar::handle:vertical {{
                background: #35404a;
                min-height: 24px;
                border-radius: 4px;
            }}
            QScrollBar::handle:vertical:hover {{ background: #46545f; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
            """
        )
        self._selected_source = None
        self._discover_thread = None
        self._discover_result = None
        self._last_discovered_paths = set()
        self._discover_poll_timer = QTimer(self)
        self._discover_poll_timer.timeout.connect(
            guarded_qt_timer(self._poll_device_discovery, "device discovery")
        )
        self._watch_timer = QTimer(self)
        self._watch_timer.setInterval(3000)
        self._watch_timer.timeout.connect(
            guarded_qt_timer(
                lambda: self._discover_devices(automatic=True), "device watch"
            )
        )

        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 14, 14, 14)
        outer.setSpacing(10)

        title = QLabel("SOURCE ACQUISITION")
        title.setStyleSheet(
            f"color: {TEXT}; font-family: '{mono_font_family()}'; font-size: 16px; "
            "font-weight: 700; letter-spacing: 1.2px;"
        )
        intro = QLabel(
            "Device discovery is intentionally idle. Start it only when attached media may be queried. "
            "Choosing an image or mounted folder does not scan its contents."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet(f"color: {MUTED}; font-size: 12px;")
        outer.addWidget(title)
        outer.addWidget(intro)

        self.device_tree = QTreeWidget()
        self.device_tree.setHeaderLabels(
            ["DEVICE", "DEVICE NAME / VOLUME", "MAKER", "SIZE", "FS", "MEDIA", "SEEN"]
        )
        self.device_tree.setRootIsDecorated(True)
        self.device_tree.setAlternatingRowColors(True)
        self.device_tree.setUniformRowHeights(True)
        self.device_tree.setColumnWidth(0, 125)
        self.device_tree.setColumnWidth(1, 170)
        self.device_tree.setColumnWidth(2, 120)
        self.device_tree.setColumnWidth(3, 75)
        self.device_tree.setColumnWidth(4, 115)
        self.device_tree.setColumnWidth(5, 110)
        self.device_tree.setColumnWidth(6, 115)
        self.device_tree.itemSelectionChanged.connect(self._selection_changed)
        outer.addWidget(self.device_tree, 1)

        self.status = QLabel("DISCOVERY NOT STARTED  /  NO DEVICE METADATA REQUESTED")
        self.status.setStyleSheet(
            f"color: {MUTED}; font-family: '{mono_font_family()}'; font-size: 10px; "
            "font-weight: 700; letter-spacing: 0.5px;"
        )
        outer.addWidget(self.status)

        source_actions = QHBoxLayout()
        self.discover_button = QPushButton("I'M READY · LIST DEVICES")
        self.discover_button.setObjectName("readSourceButton")
        self.discover_button.clicked.connect(lambda: self._discover_devices(automatic=False))
        self.image_button = QPushButton("CHOOSE IMAGE FILE…")
        self.image_button.clicked.connect(self._choose_image)
        self.mounted_button = QPushButton("CHOOSE MOUNTED FOLDER…")
        self.mounted_button.clicked.connect(self._choose_mounted)
        source_actions.addWidget(self.discover_button)
        source_actions.addStretch(1)
        source_actions.addWidget(self.image_button)
        source_actions.addWidget(self.mounted_button)
        outer.addLayout(source_actions)

        self.wait_for_source_check = QCheckBox("WAIT FOR SOURCE AFTER START")
        self.wait_for_source_check.setEnabled(bool(allow_wait_for_source))
        self.wait_for_source_check.setVisible(bool(allow_wait_for_source))
        self.wait_for_source_check.setToolTip(
            "Available for Hypersafe · Image immediately. Carv watches for the "
            "first new physical disk connected after the run starts."
        )
        self.wait_for_source_check.toggled.connect(self._set_wait_for_source)
        self.wait_for_source_info = QLabel(
            "Start Carv, then connect the source disk. Carv keeps it unmounted "
            "and begins protected imaging automatically."
        )
        self.wait_for_source_info.setWordWrap(True)
        self.wait_for_source_info.setVisible(False)
        self.wait_for_source_info.setStyleSheet(
            f"color: {WARNING}; background: transparent; font-size: 11px;"
        )
        wait_row = QHBoxLayout()
        wait_row.setContentsMargins(0, 2, 0, 0)
        wait_row.setSpacing(10)
        wait_row.addWidget(self.wait_for_source_check)
        wait_row.addWidget(self.wait_for_source_info, 1)
        outer.addLayout(wait_row)

        watch_row = QHBoxLayout()
        watch_row.setContentsMargins(0, 0, 0, 0)
        watch_row.setSpacing(16)
        self.watch_devices_check = ToggleSwitch()
        self.watch_devices_check.setToolTip(
            "Refreshes the device inventory every three seconds. Stops automatically when a new device appears."
        )
        self.watch_devices_check.toggled.connect(self._set_device_watch)
        watch_label = QLabel("WATCH FOR NEW DEVICES · EVERY 3s")
        watch_label.setStyleSheet(
            f"color: {MUTED}; font-family: '{mono_font_family()}'; font-size: 10px; "
            "font-weight: 700; letter-spacing: 0.5px;"
        )
        watch_row.addWidget(self.watch_devices_check)
        watch_row.addWidget(watch_label)
        watch_row.addStretch(1)
        outer.addLayout(watch_row)

        footer = QFrame()
        footer.setObjectName("dialogFooter")
        footer.setStyleSheet(
            f"QFrame#dialogFooter {{ background: transparent; border: none; border-top: 1px solid {BORDER}; }}"
        )
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(0, 14, 0, 0)
        footer_layout.setSpacing(8)
        footer_label = QLabel("CONFIRM SOURCE SELECTION")
        footer_label.setStyleSheet(
            f"color: {MUTED}; background: transparent; font-family: '{mono_font_family()}'; "
            "font-size: 9px; font-weight: 700; letter-spacing: 0.7px;"
        )
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.use_button = buttons.addButton("USE SELECTED SOURCE", QDialogButtonBox.ButtonRole.AcceptRole)
        self.use_button.setObjectName("dialogPrimary")
        self.use_button.setEnabled(False)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        footer_layout.addWidget(footer_label)
        footer_layout.addStretch(1)
        footer_layout.addWidget(buttons)
        outer.addSpacing(10)
        outer.addWidget(footer)

    def _set_device_watch(self, enabled: bool) -> None:
        if not enabled:
            self._watch_timer.stop()
            return
        self._discover_devices(automatic=True)
        if not self._watch_timer.isActive():
            self._watch_timer.start()

    def _discover_devices(self, automatic: bool = False) -> None:
        if self._discover_thread is not None and self._discover_thread.is_alive():
            return
        self.discover_button.setEnabled(False)
        self.discover_button.setText("REFRESHING DEVICES…")
        self.status.setText(
            "WATCHING FOR DEVICE CHANGES…" if automatic else
            "QUERYING OPERATING SYSTEM DEVICE INVENTORY…"
        )
        self._discover_result = None

        def worker() -> None:
            try:
                result = self._system_sources()
                self._discover_result = result, None, automatic
            except (OSError, subprocess.SubprocessError, ValueError) as exc:
                self._discover_result = [], exc, automatic

        self._discover_thread = threading.Thread(
            target=worker, name="carv-device-discovery", daemon=True
        )
        self._discover_thread.start()
        self._discover_poll_timer.start(100)

    def _poll_device_discovery(self) -> None:
        if self._discover_thread is not None and self._discover_thread.is_alive():
            return
        self._discover_poll_timer.stop()
        self._discover_thread = None
        sources, error, automatic = self._discover_result or ([], OSError("Device discovery returned no result."), False)
        self._discover_result = None
        self.discover_button.setEnabled(True)
        self.discover_button.setText("REFRESH DEVICES")
        if error is not None:
            self.status.setText("DEVICE DISCOVERY FAILED · WILL RETRY" if automatic else "DEVICE DISCOVERY FAILED")
            if not automatic:
                QMessageBox.warning(self, "Device discovery", f"Could not list devices:\n\n{error}")
            return

        sources = self._apply_first_seen(sources)
        discovered_paths = {str(source.get("path") or "") for source in sources if source.get("path")}
        newly_appeared = discovered_paths - self._last_discovered_paths if self._last_discovered_paths else set()
        self._last_discovered_paths = discovered_paths
        selected_path = str((self._selected_source or {}).get("path") or "")
        self.device_tree.clear()
        for source in sources:
            item = QTreeWidgetItem(
                [
                    source["path"],
                    source.get("display_name") or source["name"],
                    source["maker"],
                    source["size"],
                    source["fs"],
                    source["media"],
                    source["seen"],
                ]
            )
            item.setData(0, Qt.ItemDataRole.UserRole, dict(source))
            if source.get("is_new") or source.get("is_recent"):
                source_font = item.font(0)
                source_font.setBold(True)
                item.setFont(0, source_font)
                name_font = item.font(1)
                name_font.setBold(True)
                item.setFont(1, name_font)
                seen_font = item.font(6)
                seen_font.setBold(True)
                item.setFont(6, seen_font)
                item.setForeground(6, QBrush(QColor(ACCENT)))
            for partition in source.get("partitions") or []:
                child = QTreeWidgetItem(
                    [
                        partition["path"],
                        partition.get("display_name") or partition["name"],
                        partition["maker"],
                        partition["size"],
                        partition["fs"],
                        partition["media"],
                        "",
                    ]
                )
                child.setData(0, Qt.ItemDataRole.UserRole, dict(partition))
                for column in range(7):
                    child.setForeground(column, QBrush(QColor(MUTED)))
                child.setForeground(1, QBrush(QColor(TEXT)))
                if partition.get("is_preferred"):
                    name_font = child.font(1)
                    name_font.setBold(True)
                    child.setFont(1, name_font)
                    size_font = child.font(3)
                    size_font.setBold(True)
                    child.setFont(3, size_font)
                    child.setForeground(3, QBrush(QColor(ACCENT)))
                    child.setToolTip(
                        3,
                        "Likely Carv NTFS target: the largest reported NTFS partition on this disk.",
                    )
                item.addChild(child)
            self.device_tree.addTopLevelItem(item)
            if selected_path and source.get("path") == selected_path:
                self.device_tree.setCurrentItem(item)
            elif selected_path:
                for child_index in range(item.childCount()):
                    child = item.child(child_index)
                    if str(child.data(0, Qt.ItemDataRole.UserRole).get("path") or "") == selected_path:
                        item.setExpanded(True)
                        self.device_tree.setCurrentItem(child)
                        break
        new_count = sum(1 for source in sources if source.get("is_new"))
        if automatic and newly_appeared:
            self.watch_devices_check.setChecked(False)
            self.status.setText(
                f"NEW DEVICE DETECTED  /  {len(newly_appeared)} APPEARED SINCE LAST POLL  /  WATCH PAUSED"
            )
        elif automatic:
            self.status.setText("WATCHING · NO NEW DEVICES SINCE LAST POLL")
        else:
            self.status.setText(
                f"{new_count} NEW SOURCE{'S' if new_count != 1 else ''}  /  DEVICE INVENTORY UPDATED"
            )
        self.status.setStyleSheet(
            f"color: {ACCENT}; font-family: '{mono_font_family()}'; font-size: 10px; "
            "font-weight: 700; letter-spacing: 0.5px;"
        )

    def _selection_changed(self) -> None:
        item = self.device_tree.currentItem()
        source = item.data(0, Qt.ItemDataRole.UserRole) if item is not None else None
        self._selected_source = dict(source) if isinstance(source, dict) else None
        self.use_button.setEnabled(self._selected_source is not None)
        if self._selected_source:
            self.status.setText(
                f"SELECTED  /  {self._selected_source['path']}  /  "
                f"{self._selected_source['media']}"
            )

    def _choose_image(self) -> None:
        path, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Choose Source Image",
            str(Path.home()),
            "Disk images (*.img *.dd *.raw *.bin);;All files (*)",
        )
        if not path:
            return
        try:
            size_bytes = Path(path).stat().st_size
        except OSError:
            size_bytes = 0
        self._selected_source = {
            "path": path,
            "name": Path(path).name,
            "maker": "Image file",
            "size": self._human_bytes(size_bytes),
            "size_bytes": size_bytes,
            "fs": "Unknown",
            "media": "IMAGE · FILE",
            "health": "Stable",
            "seen": "KNOWN",
            "risk": "normal",
        }
        self.accept()

    def _set_wait_for_source(self, enabled: bool) -> None:
        self.wait_for_source_info.setVisible(bool(enabled))
        self.device_tree.setEnabled(not enabled)
        self.discover_button.setEnabled(not enabled)
        self.image_button.setEnabled(not enabled)
        self.mounted_button.setEnabled(not enabled)
        if enabled:
            self.device_tree.clearSelection()
            self._selected_source = {
                "path": WAIT_FOR_NEW_SOURCE_TOKEN,
                "name": "New disk after start",
                "maker": "Automatic source detection",
                "size": "Awaiting connection",
                "size_bytes": 0,
                "fs": "NTFS",
                "media": "NEW PHYSICAL DISK",
                "health": "Not connected",
                "seen": "WAITING AFTER START",
                "risk": "caution",
                "is_expected_path": True,
                "wait_for_new_source": True,
            }
            self.status.setText(
                "WAITING MODE SELECTED  /  CONNECT ONLY THE INTENDED SOURCE AFTER START"
            )
            self.use_button.setText("USE WAITING SOURCE")
            self.use_button.setEnabled(True)
        else:
            if bool((self._selected_source or {}).get("wait_for_new_source")):
                self._selected_source = None
            self.status.setText("SELECT A CONNECTED SOURCE OR ENABLE WAITING MODE")
            self.use_button.setText("USE SELECTED SOURCE")
            self.use_button.setEnabled(self._selected_source is not None)

    def _choose_mounted(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose Mounted Source Folder", str(Path.home()))
        if not path:
            return
        self._selected_source = {
            "path": path,
            "name": Path(path).name or path,
            "maker": "Mounted volume",
            "size": "Mounted",
            "size_bytes": 0,
            "fs": "OS filesystem",
            "media": "MOUNTED · FOLDER",
            "health": "OS readable",
            "seen": "KNOWN",
            "risk": "normal",
        }
        self.accept()

    @staticmethod
    def _human_bytes(value: int) -> str:
        amount = float(max(0, value))
        for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
            if amount < 1024.0 or unit == "TiB":
                return f"{amount:.1f} {unit}" if unit != "B" else f"{int(amount)} B"
            amount /= 1024.0
        return f"{int(value)} B"

    @staticmethod
    def _filesystem_summary(values) -> str:
        """Keep every filesystem label reported by the operating system."""
        labels = []
        for value in values:
            label = str(value or "").strip()
            if label and label.casefold() not in {item.casefold() for item in labels}:
                labels.append(label)
        return " / ".join(labels) or "—"

    @staticmethod
    def _display_device_name(device_name: str, volume_names) -> str:
        device = str(device_name or "").strip()
        volumes = []
        for value in volume_names or []:
            label = str(value or "").strip()
            if label and label.casefold() not in {item.casefold() for item in volumes}:
                volumes.append(label)
        volume_text = " / ".join(volumes)
        if volume_text and device and volume_text.casefold() != device.casefold():
            return f"{volume_text} · {device}"
        return volume_text or device or "—"

    @staticmethod
    def _diskutil_identifiers(entry) -> list[str]:
        identifiers = []

        def visit(node) -> None:
            if not isinstance(node, dict):
                return
            identifier = str(node.get("DeviceIdentifier") or "").strip()
            if identifier:
                identifiers.append(identifier)
            for child in node.get("Partitions") or []:
                visit(child)

        visit(entry)
        return identifiers

    @staticmethod
    def _lsblk_filesystems(entry) -> list[str]:
        filesystems = []

        def visit(node) -> None:
            if not isinstance(node, dict):
                return
            filesystem = str(node.get("fstype") or "").strip()
            if filesystem:
                filesystems.append(filesystem)
            for child in node.get("children") or []:
                visit(child)

        visit(entry)
        return filesystems

    @staticmethod
    def _lsblk_mount_paths(entry) -> list[str]:
        mounts = []

        def visit(node) -> None:
            if not isinstance(node, dict):
                return
            reported = node.get("mountpoints") or []
            if isinstance(reported, str):
                reported = reported.splitlines()
            for mount in reported:
                mount = str(mount or "").strip()
                if mount and mount not in mounts:
                    mounts.append(mount)
            for child in node.get("children") or []:
                visit(child)

        visit(entry)
        return mounts

    @staticmethod
    def _lsblk_volume_labels(entry) -> list[str]:
        labels = []

        def visit(node) -> None:
            if not isinstance(node, dict):
                return
            for key in ("label", "partlabel"):
                label = str(node.get(key) or "").strip()
                if label and label.casefold() not in {item.casefold() for item in labels}:
                    labels.append(label)
            for child in node.get("children") or []:
                visit(child)

        visit(entry)
        return labels

    def _lsblk_partitions(self, entry) -> list[dict]:
        partitions = []

        def visit(node) -> None:
            if not isinstance(node, dict):
                return
            node_type = str(node.get("type") or "").strip().lower()
            path = str(node.get("path") or "").strip()
            if path and node_type and node_type != "disk":
                size_bytes = int(node.get("size") or 0)
                label = str(node.get("label") or node.get("partlabel") or "").strip()
                partitions.append({
                    "path": path,
                    "name": label or Path(path).name,
                    "maker": "",
                    "size": self._human_bytes(size_bytes),
                    "size_bytes": size_bytes,
                    "fs": self._filesystem_summary([node.get("fstype")]),
                    "mount_paths": self._lsblk_mount_paths(node),
                    "media": "PARTITION",
                    "health": "Not queried",
                    "risk": "normal",
                    "seen": "PARTITION",
                    "is_partition": True,
                })
            for child in node.get("children") or []:
                visit(child)

        for child in entry.get("children") or []:
            visit(child)
        return self._mark_preferred_ntfs_partition(partitions)

    @staticmethod
    def _mark_preferred_ntfs_partition(partitions) -> list[dict]:
        """Mirror Carv's useful operator hint: prefer the largest visible NTFS partition."""
        candidates = [
            partition for partition in partitions
            if "ntfs" in str(partition.get("fs") or "").casefold()
        ]
        if candidates:
            preferred = max(candidates, key=lambda partition: int(partition.get("size_bytes") or 0))
            preferred["is_preferred"] = True
        return partitions

    def _system_sources(self):
        if sys.platform == "darwin":
            usb_identities = self._mac_usb_identities_by_disk()
            result = subprocess.run(
                ["diskutil", "list", "-plist", "physical"],
                capture_output=True,
                check=True,
                timeout=20,
            )
            payload = plistlib.loads(result.stdout)
            sources = []
            for disk in payload.get("AllDisksAndPartitions", []):
                identifier = str(disk.get("DeviceIdentifier") or "")
                if not identifier:
                    continue
                info_result = subprocess.run(
                    ["diskutil", "info", "-plist", f"/dev/{identifier}"],
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
                info = plistlib.loads(info_result.stdout) if info_result.returncode == 0 else {}
                smart = str(info.get("SMARTStatus") or "Unavailable")
                filesystem_labels = []
                volume_names = []
                mount_paths = []
                partitions = []
                for child_identifier in self._diskutil_identifiers(disk):
                    child_info = info if child_identifier == identifier else {}
                    if not child_info:
                        child_result = subprocess.run(
                            ["diskutil", "info", "-plist", f"/dev/{child_identifier}"],
                            capture_output=True,
                            check=False,
                            timeout=10,
                        )
                        child_info = (
                            plistlib.loads(child_result.stdout)
                            if child_result.returncode == 0 else {}
                        )
                    filesystem_labels.append(
                        child_info.get("FilesystemName") or child_info.get("FilesystemType")
                    )
                    volume_name = str(child_info.get("VolumeName") or "").strip()
                    if volume_name and volume_name.casefold() not in {
                        item.casefold() for item in volume_names
                    }:
                        volume_names.append(volume_name)
                    mount_path = str(child_info.get("MountPoint") or "").strip()
                    if mount_path and mount_path not in mount_paths:
                        mount_paths.append(mount_path)
                    if child_identifier != identifier:
                        child_size = int(child_info.get("TotalSize") or 0)
                        child_name = str(
                            child_info.get("VolumeName")
                            or child_info.get("MediaName")
                            or child_identifier
                        ).strip()
                        partitions.append({
                            "path": f"/dev/r{child_identifier}",
                            "name": child_name,
                            "maker": "",
                            "size": self._human_bytes(child_size),
                            "size_bytes": child_size,
                            "fs": self._filesystem_summary([
                                child_info.get("FilesystemName") or child_info.get("FilesystemType")
                            ]),
                            "mount_paths": [mount_path] if mount_path else [],
                            "media": "PARTITION",
                            "health": smart,
                            "risk": "normal",
                            "seen": "PARTITION",
                            "is_partition": True,
                        })
                partitions = self._mark_preferred_ntfs_partition(partitions)
                size_bytes = int(info.get("TotalSize") or disk.get("Size") or 0)
                solid = bool(info.get("SolidState"))
                usb_identity = usb_identities.get(identifier, {})
                device_name = str(
                    usb_identity.get("name")
                    or info.get("MediaName")
                    or info.get("IORegistryEntryName")
                    or identifier
                ).strip()
                maker = str(
                    info.get("DeviceVendor")
                    or info.get("DeviceManufacturer")
                    or usb_identity.get("maker")
                    or "—"
                ).strip()
                sources.append({
                    "path": f"/dev/r{identifier}",
                    "name": device_name,
                    "display_name": self._display_device_name(device_name, volume_names),
                    "volume_name": " / ".join(volume_names),
                    "maker": maker,
                    "size": self._human_bytes(size_bytes),
                    "size_bytes": size_bytes,
                    "fs": self._filesystem_summary(filesystem_labels),
                    "mount_paths": mount_paths,
                    "partitions": partitions,
                    "media": "SSD" if solid else "HDD / rotational",
                    "health": smart,
                    "risk": "critical" if smart.lower() in {"failing", "fail"} else "normal",
                })
            return sources
        if sys.platform.startswith("linux"):
            result = subprocess.run(
                ["lsblk", "--tree", "-J", "-b", "-o", "PATH,MODEL,VENDOR,LABEL,PARTLABEL,SIZE,FSTYPE,MOUNTPOINTS,ROTA,TYPE"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=True,
                timeout=20,
            )
            sources = []
            for row in json.loads(result.stdout).get("blockdevices", []):
                if row.get("type") != "disk":
                    continue
                size_bytes = int(row.get("size") or 0)
                device_name = str(row.get("model") or Path(str(row.get("path") or "disk")).name).strip()
                volume_names = self._lsblk_volume_labels(row)
                sources.append({
                    "path": str(row.get("path") or ""),
                    "name": device_name,
                    "display_name": self._display_device_name(device_name, volume_names),
                    "volume_name": " / ".join(volume_names),
                    "maker": str(row.get("vendor") or "—").strip(),
                    "size": self._human_bytes(size_bytes),
                    "size_bytes": size_bytes,
                    "fs": self._filesystem_summary(self._lsblk_filesystems(row)),
                    "mount_paths": self._lsblk_mount_paths(row),
                    "partitions": self._lsblk_partitions(row),
                    "media": "HDD / rotational" if bool(row.get("rota")) else "SSD / solid state",
                    "health": "Not queried",
                    "risk": "caution" if bool(row.get("rota")) else "normal",
                })
            return sources
        raise OSError(f"Device discovery is not implemented for {sys.platform}.")

    @staticmethod
    def _mac_usb_identities_by_disk() -> dict:
        """Map BSD disk names to USB product/manufacturer data when macOS exposes it."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPUSBDataType", "-json"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=10,
            )
            if result.returncode != 0:
                return {}
            payload = json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
            return {}

        identities = {}

        def visit(value, inherited_name="", inherited_maker="") -> None:
            if isinstance(value, dict):
                name = str(value.get("_name") or inherited_name or "").strip()
                maker = str(value.get("manufacturer") or inherited_maker or "").strip()
                disk_name = str(value.get("bsd_name") or "").strip()
                if disk_name.startswith("disk"):
                    identities[disk_name] = {"name": name, "maker": maker}
                for child in value.values():
                    visit(child, name, maker)
            elif isinstance(value, list):
                for child in value:
                    visit(child, inherited_name, inherited_maker)

        visit(payload)
        return identities

    def _apply_first_seen(self, sources):
        path = app_config_path().with_name(SOURCE_DEVICE_SEEN_FILENAME)
        try:
            journal = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"devices": {}}
        except (OSError, json.JSONDecodeError):
            journal = {"devices": {}}
        devices = journal.setdefault("devices", {})
        now = time.time()
        changed = False
        for source in sources:
            key = self._source_seen_key(source)
            candidate_keys = self._source_seen_candidate_keys(source)
            record = devices.get(key)
            if not isinstance(record, dict):
                for candidate_key in candidate_keys:
                    candidate = devices.get(candidate_key)
                    if isinstance(candidate, dict):
                        record = candidate
                        if candidate_key != key:
                            devices[key] = record
                            changed = True
                        break
            if not isinstance(record, dict):
                for candidate_key, candidate in devices.items():
                    if (
                        candidate_key != key
                        and isinstance(candidate, dict)
                        and self._source_seen_record_matches(source, candidate)
                    ):
                        record = candidate
                        devices[key] = record
                        changed = True
                        break
            if not isinstance(record, dict):
                record = {"first_seen": now, "last_seen": now}
                devices[key] = record
                changed = True
                source["is_new"] = True
            else:
                source["is_new"] = False
                first_seen_alias = record.get("first_seen_ts")
                if record.get("first_seen") is None and first_seen_alias is not None:
                    record["first_seen"] = first_seen_alias
                    changed = True
                last_seen_alias = record.get("last_seen_ts")
                if record.get("last_seen") is None and last_seen_alias is not None:
                    record["last_seen"] = last_seen_alias
                    changed = True
                previous_last_seen = float(record.get("last_seen") or record.get("first_seen") or now)
                if abs(previous_last_seen - now) >= 0.5:
                    record["last_seen"] = now
                    changed = True
                else:
                    record["last_seen"] = now
            if record.get("path") != source.get("path"):
                record["path"] = str(source.get("path") or "")
                changed = True
            if record.get("identity_version") != 3:
                record["identity_version"] = 3
                changed = True
            if record.get("name") != source.get("name"):
                record["name"] = str(source.get("name") or "")
                changed = True
            if record.get("maker") != source.get("maker"):
                record["maker"] = str(source.get("maker") or "")
                changed = True
            size_bytes = int(source.get("size_bytes") or 0)
            if record.get("size_bytes") != size_bytes:
                record["size_bytes"] = size_bytes
                changed = True
            if record.get("fs") != source.get("fs"):
                record["fs"] = str(source.get("fs") or "")
                changed = True
            first_seen = float(record.get("first_seen") or record.get("first_seen_ts") or now)
            last_seen = float(record.get("last_seen") or record.get("last_seen_ts") or first_seen or now)
            source["first_seen_order"] = first_seen
            source["last_seen_order"] = last_seen
            if source["is_new"]:
                source["seen"] = "● NEW · now"
                source["is_recent"] = True
            else:
                first_seen_date = datetime.fromtimestamp(first_seen).date()
                days_since_first_seen = (datetime.now().date() - first_seen_date).days
                if days_since_first_seen == 0:
                    source["seen"] = "● FIRST SEEN TODAY"
                    source["is_recent"] = True
                elif days_since_first_seen == 1:
                    source["seen"] = "● FIRST SEEN YESTERDAY"
                    source["is_recent"] = True
                else:
                    source["seen"] = time.strftime("FIRST SEEN · %Y-%m-%d", time.localtime(first_seen))
        if changed:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                temp_path = path.with_suffix(path.suffix + ".tmp")
                temp_path.write_text(json.dumps(journal, indent=2, sort_keys=True), encoding="utf-8")
                temp_path.replace(path)
            except OSError:
                pass
        return sorted(sources, key=lambda source: (-float(source.get("last_seen_order") or 0), source.get("path", "")))

    @staticmethod
    def _source_seen_identity(source, *, stable: bool) -> dict:
        path = str(source.get("path") or "")
        media = str(source.get("media") or "")
        if "IMAGE" in media or "MOUNTED" in media or not path.startswith("/dev/"):
            identity = {
                "kind": "path",
                "path": path,
                "size_bytes": int(source.get("size_bytes") or 0),
            }
        else:
            partitions = []
            for partition in source.get("partitions") or []:
                if not isinstance(partition, dict):
                    continue
                partition_identity = {
                    "size_bytes": int(partition.get("size_bytes") or 0),
                }
                if not stable:
                    partition_identity.update({
                        "name": str(partition.get("name") or ""),
                        "fs": str(partition.get("fs") or ""),
                    })
                partitions.append(partition_identity)
            identity = {
                "kind": "block-device",
                "name": str(source.get("name") or ""),
                "maker": str(source.get("maker") or ""),
                "media": media,
                "size_bytes": int(source.get("size_bytes") or 0),
                "partitions": sorted(
                    partitions,
                    key=lambda item: (
                        item["size_bytes"],
                        str(item.get("fs") or "").casefold(),
                        str(item.get("name") or "").casefold(),
                    ),
                ),
            }
            if not stable:
                identity["fs"] = str(source.get("fs") or "")
        return identity

    @staticmethod
    def _source_seen_digest(identity: dict, version: int) -> str:
        encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        return f"v{version}:{digest}"

    @staticmethod
    def _source_seen_key(source) -> str:
        return SourcePickerDialog._source_seen_digest(
            SourcePickerDialog._source_seen_identity(source, stable=True),
            3,
        )

    @staticmethod
    def _source_seen_candidate_keys(source) -> list[str]:
        keys = []
        for version, stable in ((3, True), (2, False)):
            key = SourcePickerDialog._source_seen_digest(
                SourcePickerDialog._source_seen_identity(source, stable=stable),
                version,
            )
            if key not in keys:
                keys.append(key)
        path = str(source.get("path") or "")
        media = str(source.get("media") or "")
        if path and ("IMAGE" in media or "MOUNTED" in media or not path.startswith("/dev/")) and path not in keys:
            keys.append(path)
        return keys

    @staticmethod
    def _source_seen_record_matches(source, record: dict) -> bool:
        source_size = int(source.get("size_bytes") or 0)
        record_size = int(record.get("size_bytes") or 0)
        if source_size <= 0 or record_size <= 0 or source_size != record_size:
            return False
        source_name = str(source.get("name") or "").strip().casefold()
        record_name = str(record.get("name") or record.get("label") or "").strip().casefold()
        if source_name and record_name and source_name != record_name:
            return False
        source_maker = str(source.get("maker") or "").strip().casefold()
        record_maker = str(record.get("maker") or record.get("manufacturer") or "").strip().casefold()
        if source_maker not in {"", "—"} and record_maker not in {"", "—"} and source_maker != record_maker:
            return False
        return bool(source_name or record_name)

    def selected_source(self):
        return dict(self._selected_source) if self._selected_source else None


class SourceTreePanel(QFrame):
    """Source workspace that remains inactive until the operator requests a preview."""

    def __init__(
        self,
        source_changed_callback=None,
        folder_selection_callback=None,
        test_recovery_callback=None,
    ) -> None:
        super().__init__()
        self._source_changed_callback = source_changed_callback
        self._folder_selection_callback = folder_selection_callback
        self._test_recovery_callback = test_recovery_callback
        self._allow_wait_for_source = False
        self._source = None
        self._source_preview_route = ""
        self._mode = "signature"
        self._tree_loaded = False
        self._preview_thread = None
        self._preview_result = None
        self._preview_cancel_event = threading.Event()
        self._preview_process_lock = threading.Lock()
        self._preview_process = None
        self._setup_sudo_ready = False
        self._setup_sudo_environment = None
        self._sudo_keepalive_timer = QTimer(self)
        self._sudo_keepalive_timer.setInterval(60_000)
        self._sudo_keepalive_timer.timeout.connect(
            guarded_qt_timer(self._refresh_preview_sudo_lease, "sudo keepalive")
        )
        self._preview_timer = QTimer(self)
        self._preview_timer.timeout.connect(
            guarded_qt_timer(self._poll_source_tree_preview, "source tree preview")
        )
        self._child_preview_thread = None
        self._child_preview_result = None
        self._child_preview_item = None
        self._child_preview_folder = ""
        self._child_cache = {}
        self._child_prefetch_queue = []
        self._child_prefetch_total = 0
        self._child_prefetch_done = 0
        self._source_tree_cache_key = ""
        self._source_tree_cache_signature = None
        self._prefetch_animation_step = 0
        self._prefetch_animation_paused = False
        self._prefetch_animation_timer = QTimer(self)
        self._prefetch_animation_timer.setInterval(105)
        self._prefetch_animation_timer.timeout.connect(
            guarded_qt_timer(self._advance_prefetch_animation, "prefetch animation")
        )
        self._source_generation = 0
        self._child_preview_timer = QTimer(self)
        self._child_preview_timer.timeout.connect(
            guarded_qt_timer(self._poll_child_folder_preview, "child folder preview")
        )
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        box = group_box("02  /  SOURCE")
        layout = QVBoxLayout(box)
        layout.setContentsMargins(12, 16, 12, 12)
        layout.setSpacing(8)

        self.source_bar = QFrame()
        self.source_bar.setObjectName("sourceBar")
        self.source_bar.setStyleSheet(
            f"QFrame#sourceBar {{ background: #14191e; border: 1px solid {BORDER}; border-radius: 4px; }}"
        )
        self.source_bar.setToolTip(
            "Current source information. Use SELECT SOURCE below to change it."
        )
        source_bar_layout = QVBoxLayout(self.source_bar)
        source_bar_layout.setContentsMargins(10, 7, 10, 8)
        source_bar_layout.setSpacing(3)
        source_heading = QLabel("CURRENT SOURCE")
        source_heading.setStyleSheet(
            f"color: {MUTED}; background: transparent; font-family: '{mono_font_family()}'; "
            "font-size: 8px; font-weight: 700; letter-spacing: 1px;"
        )
        source_bar_layout.addWidget(source_heading)
        source_detail_row = QHBoxLayout()
        source_detail_row.setContentsMargins(0, 0, 0, 0)
        source_detail_row.setSpacing(8)
        self.device_label = QLabel("NONE SELECTED")
        self.device_label.setStyleSheet(
            f"color: {TEXT}; background: transparent; font-family: '{mono_font_family()}'; "
            "font-size: 10px; font-weight: 700; letter-spacing: 0.5px;"
        )
        self.source_meta = QLabel("AWAITING SELECTION")
        self.source_meta.setStyleSheet(
            f"color: {ACCENT}; background: transparent; font-family: '{mono_font_family()}'; "
            "font-size: 10px; font-weight: 700; letter-spacing: 0.8px;"
        )
        source_detail_row.addWidget(self.device_label)
        source_detail_row.addStretch(1)
        source_detail_row.addWidget(self.source_meta)
        source_bar_layout.addLayout(source_detail_row)
        layout.addWidget(self.source_bar)

        choose_row = QHBoxLayout()
        choose_row.setContentsMargins(0, 0, 0, 0)
        choose_row.setSpacing(6)
        choose_source = QPushButton("SELECT SOURCE…")
        choose_source.clicked.connect(self._open_source_picker)
        choose_row.addWidget(choose_source)
        self.test_jpegs_button = QPushButton("TEST 10 JPGS")
        self.test_jpegs_button.setEnabled(False)
        self.test_jpegs_button.setToolTip(
            "Recover up to 10 JPEGs from filesystem metadata into recovered/test."
        )
        self.test_jpegs_button.clicked.connect(self._request_test_recovery)
        choose_row.addWidget(self.test_jpegs_button)
        choose_row.addStretch(1)
        layout.addLayout(choose_row)

        self.safety = QFrame()
        self.safety.setObjectName("sourceSafety")
        self.safety.setStyleSheet(
            f"QFrame#sourceSafety {{ background: #101519; border: 1px solid {BORDER}; border-radius: 4px; }}"
        )
        safety_layout = QVBoxLayout(self.safety)
        safety_layout.setContentsMargins(18, 18, 18, 18)
        safety_layout.setSpacing(10)
        safety_layout.addStretch(1)

        self.locked_label = QLabel("CHOOSE SOURCE")
        self.locked_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.locked_label.setStyleSheet(
            f"color: {TEXT}; background: transparent; font-family: '{mono_font_family()}'; "
            "font-size: 15px; font-weight: 700; letter-spacing: 1.5px;"
        )
        self.explanation = QLabel("")
        self.explanation.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.explanation.setWordWrap(True)
        self.explanation.setStyleSheet(
            f"color: {MUTED}; background: transparent; font-size: 12px; line-height: 1.4;"
        )
        self.read_tree = QPushButton("READ SOURCE STRUCTURE")
        self.read_tree.setObjectName("readSourceButton")
        self.read_tree.setEnabled(False)
        self.read_tree.setToolTip("Enabled after a source is selected. This action may read from the physical source.")
        self.read_tree.clicked.connect(self._read_source_tree)
        self.preview_progress = QProgressBar()
        self.preview_progress.setRange(0, 0)
        self.preview_progress.setTextVisible(False)
        self.preview_progress.setFixedHeight(8)
        self.preview_progress.setStyleSheet(
            f"QProgressBar {{ background: #0d1216; border: 1px solid {BORDER}; border-radius: 2px; }}"
            f"QProgressBar::chunk {{ background: {ACCENT}; border-radius: 1px; }}"
        )
        self.preview_progress.setVisible(False)
        decision_row = QHBoxLayout()
        decision_row.setSpacing(8)
        decision_row.addStretch(1)
        decision_row.addWidget(self.read_tree)
        decision_row.addStretch(1)

        safety_layout.addWidget(self.locked_label)
        safety_layout.addWidget(self.explanation)
        safety_layout.addWidget(self.preview_progress)
        safety_layout.addLayout(decision_row)
        safety_layout.addStretch(1)
        layout.addWidget(self.safety, 1)

        self.source_tree = QTreeWidget()
        self.source_tree.setHeaderLabels(["FOLDER", "SCOPE", "SELECTION"])
        self.source_tree.setColumnWidth(0, 245)
        self.source_tree.setColumnWidth(1, 90)
        self.source_tree.setRootIsDecorated(True)
        self.source_tree.setAlternatingRowColors(True)
        self.source_tree.setUniformRowHeights(True)
        self.source_tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.source_tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.source_tree.itemSelectionChanged.connect(self._update_folder_selection)
        self.source_tree.itemExpanded.connect(self._load_child_folders)
        self.source_tree.setVisible(False)
        layout.addWidget(self.source_tree, 1)

        action_row = QHBoxLayout()
        action_row.setContentsMargins(0, 0, 0, 0)
        action_row.setSpacing(8)
        self.tree_state = QLabel("TREE  /  INACTIVE")
        self.tree_state.setStyleSheet(
            f"color: {MUTED}; background: transparent; font-family: '{mono_font_family()}'; "
            "font-size: 9px; font-weight: 700; letter-spacing: 0.6px;"
        )
        action_row.addWidget(self.tree_state)
        action_row.addStretch(1)
        layout.addLayout(action_row)
        outer.addWidget(box)

    @staticmethod
    def _source_needs_sudo(source) -> bool:
        return str((source or {}).get("path") or "").startswith("/dev/")

    @staticmethod
    def _source_preview_needs_sudo(source) -> bool:
        return (
            SourceTreePanel._source_needs_sudo(source)
            and not str((source or {}).get("_hypersafe_image_path") or "")
        )

    def _ensure_preview_sudo_lease(self, source) -> tuple[bool, str]:
        if not self._source_preview_needs_sudo(source):
            self._setup_sudo_ready = False
            self._setup_sudo_environment = None
            return True, ""
        if self._setup_sudo_ready:
            if not self._sudo_keepalive_timer.isActive():
                self._sudo_keepalive_timer.start()
            return True, ""
        ok, environment, _error = ensure_sudo_credential(
            "Preview filesystem structure",
            "Carv needs permission to keep reading folder metadata from this source.",
            "Keep reading",
            cwd=str(app_runtime_root()),
            noninteractive=True,
        )
        if ok:
            self._setup_sudo_ready = True
            self._setup_sudo_environment = environment
            if not self._sudo_keepalive_timer.isActive():
                self._sudo_keepalive_timer.start()
            return True, ""
        if self._setup_sudo_ready:
            self._setup_sudo_ready = False
            self._setup_sudo_environment = None
        ok, _environment, error = ensure_sudo_credential(
            "Preview filesystem structure",
            "Carv needs permission to read folder metadata from this source.",
            "Read source",
            cwd=str(app_runtime_root()),
            noninteractive=False,
        )
        if ok and not self._sudo_keepalive_timer.isActive():
            self._sudo_keepalive_timer.start()
        self._setup_sudo_ready = bool(ok)
        if ok:
            self._setup_sudo_environment = _environment
        else:
            self._setup_sudo_environment = None
        return ok, error

    def _refresh_preview_sudo_lease(self) -> None:
        if not self._source_preview_needs_sudo(self._source):
            self._sudo_keepalive_timer.stop()
            self._setup_sudo_environment = None
            return
        ok, _environment, _error = ensure_sudo_credential(
            "Preview filesystem structure",
            "Carv needs permission to keep reading folder metadata from this source.",
            "Keep reading",
            cwd=str(app_runtime_root()),
            noninteractive=True,
        )
        if not ok:
            self._setup_sudo_ready = False
            self._setup_sudo_environment = None
            self._sudo_keepalive_timer.stop()
        else:
            self._setup_sudo_environment = _environment

    def release_setup_sudo_for_recovery(self) -> None:
        self._sudo_keepalive_timer.stop()
        self._setup_sudo_ready = False
        self._setup_sudo_environment = None
        if self._source_needs_sudo(self._source):
            expire_sudo_credential(str(app_runtime_root()))

    def _preview_sudo_environment(self, base=None) -> dict:
        environment, error = sudo_askpass_environment(
            "Preview filesystem structure",
            "Carv needs permission to read folder metadata from this source.",
            "Read source",
            base=base,
        )
        if error:
            return dict(os.environ if base is None else base)
        return environment

    @staticmethod
    def _source_tree_cache_path() -> Path:
        return app_config_path().with_name(SOURCE_TREE_CACHE_FILENAME)

    @classmethod
    def _load_source_tree_cache(cls) -> dict:
        path = cls._source_tree_cache_path()
        try:
            cache = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        except (OSError, json.JSONDecodeError):
            cache = {}
        if not isinstance(cache, dict):
            cache = {}
        entries = cache.get("entries")
        if not isinstance(entries, dict):
            cache = {"version": 1, "entries": {}}
        return cache

    @classmethod
    def _write_source_tree_cache(cls, cache: dict) -> None:
        path = cls._source_tree_cache_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(cache, indent=2, sort_keys=True), encoding="utf-8")
        except OSError:
            pass

    @staticmethod
    def _mac_source_identity(path: str) -> dict:
        if sys.platform != "darwin" or not path:
            return {}
        disk_path = path.replace("/dev/rdisk", "/dev/disk", 1)
        try:
            result = subprocess.run(
                ["diskutil", "info", "-plist", disk_path],
                capture_output=True,
                check=False,
                timeout=4,
            )
            if result.returncode != 0:
                return {}
            info = plistlib.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, ValueError):
            return {}
        keys = (
            "DeviceIdentifier", "VolumeUUID", "DiskUUID", "MediaUUID",
            "FilesystemName", "FilesystemType", "VolumeName", "TotalSize",
            "MountPoint",
        )
        return {
            str(key): str(info.get(key) or "")
            for key in keys
            if str(info.get(key) or "")
        }

    @staticmethod
    def _linux_source_identity(path: str) -> dict:
        if not sys.platform.startswith("linux") or not path or not shutil.which("lsblk"):
            return {}
        try:
            result = subprocess.run(
                [
                    "lsblk", "-J", "-b", "--nodeps",
                    "-o", "PATH,UUID,PARTUUID,LABEL,FSTYPE,SIZE,MOUNTPOINTS",
                    path,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=4,
            )
            if result.returncode != 0:
                return {}
            rows = json.loads(result.stdout).get("blockdevices") or []
            row = rows[0] if rows else {}
        except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
            return {}
        return {
            str(key): str(row.get(key.lower()) or row.get(key) or "")
            for key in ("PATH", "UUID", "PARTUUID", "LABEL", "FSTYPE", "SIZE", "MOUNTPOINTS")
            if str(row.get(key.lower()) or row.get(key) or "")
        }

    @staticmethod
    def _mounted_tree_identity(path: str) -> dict:
        if not path:
            return {}
        try:
            stat = Path(path).stat()
        except (OSError, ValueError):
            return {}
        return {
            "mount_path": str(path),
            "mount_dev": str(getattr(stat, "st_dev", "")),
            "mount_inode": str(getattr(stat, "st_ino", "")),
            "mount_mtime_ns": str(getattr(stat, "st_mtime_ns", "")),
        }

    @staticmethod
    def _u16be(data: bytes, offset: int) -> int:
        return int.from_bytes(data[offset:offset + 2], "big", signed=False)

    @staticmethod
    def _u32be(data: bytes, offset: int) -> int:
        return int.from_bytes(data[offset:offset + 4], "big", signed=False)

    @staticmethod
    def _u32le(data: bytes, offset: int) -> int:
        return int.from_bytes(data[offset:offset + 4], "little", signed=False)

    @staticmethod
    def _u64le(data: bytes, offset: int) -> int:
        return int.from_bytes(data[offset:offset + 8], "little", signed=False)

    @staticmethod
    def _is_power_of_two(value: int) -> bool:
        return value > 0 and (value & (value - 1)) == 0

    def _read_source_bytes(self, path: str, offset: int, length: int) -> bytes:
        if not path or offset < 0 or length <= 0:
            return b""
        try:
            with open(path, "rb", buffering=0) as handle:
                handle.seek(offset)
                return handle.read(length)
        except (OSError, ValueError):
            pass
        if not path.startswith("/dev/"):
            return b""
        if offset % 512 != 0 or length % 512 != 0:
            return b""
        command = [
            "sudo", "-n", "dd",
            f"if={path}",
            "bs=512",
            f"skip={offset // 512}",
            f"count={max(1, length // 512)}",
        ]
        try:
            result = subprocess.run(
                command,
                cwd=str(app_runtime_root()),
                env=self._preview_sudo_environment(),
                capture_output=True,
                check=False,
                timeout=8,
            )
        except (OSError, subprocess.SubprocessError):
            return b""
        if result.returncode != 0 and sudo_auth_failed_text(result.stderr):
            self._setup_sudo_ready = False
            self._setup_sudo_environment = None
            return b""
        if result.returncode != 0:
            return b""
        return bytes(result.stdout[:length])

    def _parse_hfsplus_header_at(self, path: str, volume_offset: int, *, has_wrapper: bool = False) -> dict:
        header_offset = int(volume_offset) + 1024
        header = self._read_source_bytes(path, header_offset, 512)
        if len(header) < 512:
            return {}
        signature = self._u16be(header, 0)
        version = self._u16be(header, 2)
        if (signature, version) not in {(0x482B, 4), (0x4858, 5)}:
            return {}
        block_size = self._u32be(header, 40)
        total_blocks = self._u32be(header, 44)
        if (
            not self._is_power_of_two(block_size)
            or block_size < 512
            or total_blocks <= 0
        ):
            return {}
        attributes = self._u32be(header, 4)
        volume_size = block_size * total_blocks
        return {
            "signature": "HFSX" if signature == 0x4858 else "HFS+",
            "version": version,
            "volume_offset": int(volume_offset),
            "header_offset": header_offset,
            "has_wrapper": bool(has_wrapper),
            "attributes": f"0x{attributes:08x}",
            "journaled": bool(attributes & 0x00002000),
            "last_mounted_version": header[8:12].decode("latin-1", errors="replace"),
            "journal_info_block": self._u32be(header, 12),
            "create_date": self._u32be(header, 16),
            "modify_date": self._u32be(header, 20),
            "backup_date": self._u32be(header, 24),
            "checked_date": self._u32be(header, 28),
            "file_count": self._u32be(header, 32),
            "folder_count": self._u32be(header, 36),
            "block_size": block_size,
            "total_blocks": total_blocks,
            "free_blocks": self._u32be(header, 48),
            "next_allocation": self._u32be(header, 52),
            "next_catalog_id": self._u32be(header, 64),
            "write_count": self._u32be(header, 68),
            "volume_size": volume_size,
        }

    def _probe_hfsplus_candidate(self, path: str, candidate_offset: int) -> dict:
        direct = self._parse_hfsplus_header_at(path, candidate_offset)
        if direct:
            return direct
        mdb = self._read_source_bytes(path, int(candidate_offset) + 1024, 512)
        if len(mdb) < 512:
            return {}
        wrapper_signature = self._u16be(mdb, 0)
        embedded_signature = self._u16be(mdb, 124)
        wrapper_block_size = self._u32be(mdb, 20)
        wrapper_first_block = self._u16be(mdb, 28)
        embedded_start_block = self._u16be(mdb, 126)
        if (
            wrapper_signature != 0x4244
            or embedded_signature not in {0x482B, 0x4858}
            or wrapper_block_size <= 0
        ):
            return {}
        embedded_offset = (
            int(candidate_offset)
            + (wrapper_first_block * 512)
            + (embedded_start_block * wrapper_block_size)
        )
        return self._parse_hfsplus_header_at(path, embedded_offset, has_wrapper=True)

    def _hfsplus_header_signature(self, source) -> dict:
        path = str((source or {}).get("path") or "")
        if not path:
            return {}
        candidates = [0]
        gpt = self._read_source_bytes(path, 512, 512)
        if len(gpt) >= 512 and gpt.startswith(b"EFI PART"):
            entries_lba = self._u64le(gpt, 72)
            entry_count = min(self._u32le(gpt, 80), 4096)
            entry_size = self._u32le(gpt, 84)
            if entries_lba > 0 and entry_count > 0 and 128 <= entry_size <= 4096:
                table_bytes = entry_count * entry_size
                read_bytes = ((table_bytes + 511) // 512) * 512
                table = self._read_source_bytes(path, entries_lba * 512, read_bytes)
                for index in range(entry_count):
                    start = index * entry_size
                    entry = table[start:start + entry_size]
                    if len(entry) < 48 or not any(entry[:16]):
                        continue
                    first_lba = self._u64le(entry, 32)
                    last_lba = self._u64le(entry, 40)
                    if first_lba > 0 and last_lba >= first_lba:
                        candidates.append(first_lba * 512)
        mbr = self._read_source_bytes(path, 0, 512)
        if len(mbr) >= 512 and mbr[510:512] == b"\x55\xaa":
            for index in range(4):
                start = 446 + (index * 16)
                entry = mbr[start:start + 16]
                if len(entry) < 16 or entry[4] in {0x00, 0xEE}:
                    continue
                start_lba = self._u32le(entry, 8)
                sector_count = self._u32le(entry, 12)
                if start_lba > 0 and sector_count > 0:
                    candidates.append(start_lba * 512)
        seen = set()
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            signature = self._probe_hfsplus_candidate(path, int(candidate))
            if signature:
                return signature
        return {}

    def _source_cache_signature(self, source) -> tuple[str, dict]:
        source_path = str(source.get("path") or "")
        mounted_path = str(source.get("_browse_mount_path") or self._mounted_preview_path(source))
        signature = {
            "path": source_path,
            "name": str(source.get("name") or ""),
            "maker": str(source.get("maker") or ""),
            "size_bytes": int(source.get("size_bytes") or 0),
            "fs": self._normalize_filesystem_label(
                source.get("_interpreted_filesystem")
                or source.get("_filesystem")
                or source.get("fs")
                or ""
            ),
            "partitions": [
                {
                    "path": str(partition.get("path") or ""),
                    "size_bytes": int(partition.get("size_bytes") or 0),
                    "fs": str(partition.get("fs") or ""),
                    "name": str(partition.get("name") or ""),
                }
                for partition in (source.get("partitions") or [])
                if isinstance(partition, dict)
            ],
            "mount": self._mounted_tree_identity(mounted_path),
            "mac": self._mac_source_identity(source_path),
            "linux": self._linux_source_identity(source_path),
            "hfsplus_header": self._hfsplus_header_signature(source),
        }
        encoded = json.dumps(signature, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest(), signature

    def _current_source_cache_identity(self, source) -> tuple[str, dict]:
        if self._source_tree_cache_key and isinstance(self._source_tree_cache_signature, dict):
            return self._source_tree_cache_key, dict(self._source_tree_cache_signature)
        cache_key, signature = self._source_cache_signature(source)
        self._source_tree_cache_key = cache_key
        self._source_tree_cache_signature = dict(signature)
        return cache_key, signature

    @staticmethod
    def _cached_child_map(child_cache) -> dict:
        cached = {}
        for folder, value in (child_cache or {}).items():
            if not isinstance(value, (list, tuple)) or len(value) < 2:
                continue
            children, error = value[0], value[1]
            if error:
                continue
            cached[str(folder)] = list(children or [])
        return cached

    @staticmethod
    def _utf8_preview_environment() -> dict:
        environment = os.environ.copy()
        environment.setdefault("PYTHONUTF8", "1")
        locale_name = str(
            environment.get("LC_ALL")
            or environment.get("LC_CTYPE")
            or environment.get("LANG")
            or ""
        )
        if "utf-8" not in locale_name.lower() and "utf8" not in locale_name.lower():
            environment.pop("LC_ALL", None)
            utf8_locale = "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8"
            environment["LC_CTYPE"] = utf8_locale
            environment["LANG"] = utf8_locale
        return environment

    @staticmethod
    def _sanitize_preview_line(line: str) -> str:
        """Remove terminal decoration and backend log messages from folder output."""
        value = ANSI_ESCAPE_RE.sub("", str(line or ""))
        value = TERMINAL_CONTROL_RE.sub("", value).strip()
        # Also tolerate CSI introducers that have already been rendered or
        # replaced before reaching us (for example "�[0m�[39mFolder").
        value = re.sub(r"^(?:(?:\ufffd)?\[[0-9;?]+[A-Za-z])+", "", value).strip()
        if not value or re.match(
            r"^\[(?:TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|FATAL)\]\s*",
            value,
            flags=re.IGNORECASE,
        ):
            return ""
        if value.casefold() in {".", "..", "$extend"}:
            return ""
        return value

    @classmethod
    def _preview_error_text(cls, text: str, fallback: str) -> str:
        cleaned = ANSI_ESCAPE_RE.sub("", str(text or ""))
        cleaned = TERMINAL_CONTROL_RE.sub("", cleaned)
        lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
        return "\n".join(lines[:6]) or fallback

    def _open_source_picker(self) -> None:
        dialog = SourcePickerDialog(
            self,
            allow_wait_for_source=self._allow_wait_for_source,
        )
        if dialog.exec():
            source = dialog.selected_source()
            if source:
                self._apply_source(source)

    def set_wait_for_source_enabled(self, enabled: bool) -> None:
        self._allow_wait_for_source = bool(enabled)

    def _request_test_recovery(self) -> None:
        if self._test_recovery_callback is not None:
            self._test_recovery_callback()

    def set_test_recovery_running(self, running: bool) -> None:
        if not hasattr(self, "test_jpegs_button"):
            return
        self.test_jpegs_button.setEnabled(False if running else self._source is not None)
        self.test_jpegs_button.setText("TESTING JPGS…" if running else "TEST 10 JPGS")

    def _apply_source(self, source) -> None:
        self._cancel_folder_discovery()
        self._preview_cancel_event.clear()
        self._source_generation += 1
        self._stop_prefetch_activity()
        self._source = dict(source)
        self._source_preview_route = ""
        self._tree_loaded = False
        self._child_cache.clear()
        self._setup_sudo_ready = False
        self._setup_sudo_environment = None
        self._source_tree_cache_key = ""
        self._source_tree_cache_signature = None
        self._child_prefetch_queue.clear()
        self._child_prefetch_total = 0
        self._child_prefetch_done = 0
        self.source_tree.clear()
        self.source_tree.setVisible(False)
        self.safety.setVisible(True)
        self.preview_progress.setVisible(False)
        waiting_source = bool(self._source.get("wait_for_new_source"))
        self.test_jpegs_button.setEnabled(not waiting_source)
        if self._folder_selection_callback is not None:
            self._folder_selection_callback([])
        self.device_label.setText(
            "NEW DISK AFTER START"
            if waiting_source
            else f"{source['path']}  ·  {source['name']}"
        )
        self._restore_source_meta()
        self._refresh_source_plan()
        if self._source_changed_callback is not None:
            self._source_changed_callback(self._source)
        if self._source_preview_needs_sudo(self._source):
            self.tree_state.setText("TREE  /  INACTIVE · SUDO ON PREVIEW")
            self.read_tree.setToolTip(
                "Sudo will be requested if you preview the file tree from this source."
            )
        else:
            self.read_tree.setToolTip("")

    def _advance_prefetch_animation(self) -> None:
        if not self._prefetch_animation_timer.isActive():
            return
        if self._prefetch_animation_paused:
            self._prefetch_animation_paused = False
            self._prefetch_animation_step = 0
            self._prefetch_animation_timer.setInterval(105)
        elif self._prefetch_animation_step >= len("PREFETCH") - 1:
            self._prefetch_animation_paused = True
            self._prefetch_animation_timer.setInterval(500)
        else:
            self._prefetch_animation_step += 1
        self._show_prefetch_activity()

    def _show_prefetch_activity(self) -> None:
        """Draw a restrained moving highlight across the background prefetch label."""
        label = "PREFETCH"
        active = (
            set()
            if self._prefetch_animation_paused else
            {
                index for index in range(
                    self._prefetch_animation_step,
                    min(self._prefetch_animation_step + 3, len(label)),
                )
            }
        )
        highlighted = "#25dd8a"
        resting = "#079b5b"
        animated_label = "".join(
            f'<span style="color: {highlighted if index in active else resting};">{letter}</span>'
            for index, letter in enumerate(label)
        )
        total = max(self._child_prefetch_total, self._child_prefetch_done)
        filesystem = self._interpreted_filesystem_label()
        self.source_meta.setTextFormat(Qt.TextFormat.RichText)
        self.source_meta.setText(
            f"FILESYSTEM · {filesystem}  ·  "
            f"{animated_label}  ·  {self._child_prefetch_done}/{total}"
        )

    def _start_prefetch_activity(self) -> None:
        self._prefetch_animation_step = 0
        self._prefetch_animation_paused = False
        self._prefetch_animation_timer.setInterval(105)
        self._show_prefetch_activity()
        if not self._prefetch_animation_timer.isActive():
            self._prefetch_animation_timer.start()

    def _stop_prefetch_activity(self) -> None:
        self._prefetch_animation_timer.stop()
        self._prefetch_animation_step = 0
        self._prefetch_animation_paused = False
        self._prefetch_animation_timer.setInterval(105)

    def _restore_source_meta(self) -> None:
        self.source_meta.setTextFormat(Qt.TextFormat.PlainText)
        filesystem = self._interpreted_filesystem_label()
        if bool((self._source or {}).get("wait_for_new_source")):
            self.source_meta.setText("WAITING FOR NEW DISK AFTER START")
            self.source_meta.setStyleSheet(
                f"color: {WARNING}; background: transparent; font-family: '{mono_font_family()}'; "
                "font-size: 10px; font-weight: 700; letter-spacing: 0.8px;"
            )
        elif self._source_preview_route == "os":
            self.source_meta.setText(f"FILESYSTEM · {filesystem}  ·  OS TREE · MOUNTED")
            self.source_meta.setStyleSheet(
                f"color: {ACCENT}; background: transparent; font-family: '{mono_font_family()}'; "
                "font-size: 10px; font-weight: 700; letter-spacing: 0.8px;"
            )
        elif self._source_preview_route == "metadata":
            self.source_meta.setText(f"FILESYSTEM · {filesystem}  ·  METADATA TREE")
            self.source_meta.setStyleSheet(
                f"color: #d0a05a; background: transparent; font-family: '{mono_font_family()}'; "
                "font-size: 10px; font-weight: 700; letter-spacing: 0.8px;"
            )
        elif self._source_preview_route == "metadata-cache":
            self.source_meta.setText(f"FILESYSTEM · {filesystem}  ·  METADATA TREE · CACHE")
            self.source_meta.setStyleSheet(
                f"color: #d0a05a; background: transparent; font-family: '{mono_font_family()}'; "
                "font-size: 10px; font-weight: 700; letter-spacing: 0.8px;"
            )
        elif self._source_preview_route == "metadata-hypersafe":
            self.source_meta.setText(f"FILESYSTEM · {filesystem}  ·  HYPERSAFE MFT IMAGE")
            self.source_meta.setStyleSheet(
                f"color: #d0a05a; background: transparent; font-family: '{mono_font_family()}'; "
                "font-size: 10px; font-weight: 700; letter-spacing: 0.8px;"
            )
        elif self._source:
            self.source_meta.setText(f"{self._source['size']}  ·  {self._source['seen']}")
            self.source_meta.setStyleSheet(
                f"color: {ACCENT}; background: transparent; font-family: '{mono_font_family()}'; "
                "font-size: 10px; font-weight: 700; letter-spacing: 0.8px;"
            )

    @staticmethod
    def _normalize_filesystem_label(value: str) -> str:
        text = str(value or "").strip()
        lowered = text.casefold()
        if "hfs+" in lowered or "hfsplus" in lowered or "apple_hfs" in lowered:
            return "HFS+"
        if "ntfs" in lowered:
            return "NTFS"
        if "exfat" in lowered:
            return "exFAT"
        if "fat32" in lowered or lowered in {"vfat", "msdos", "fat"}:
            return "FAT32"
        if "apfs" in lowered:
            return "APFS"
        return text if text and lowered not in {"auto", "auto detect"} else "DETECTING"

    def _interpreted_filesystem_label(self) -> str:
        source = self._source or {}
        interpreted = str(source.get("_interpreted_filesystem") or "")
        if interpreted:
            return self._normalize_filesystem_label(interpreted)
        requested = str(source.get("_preview_filesystem") or "")
        if requested and requested != "auto detect":
            return self._normalize_filesystem_label(requested)
        return self._normalize_filesystem_label(str(source.get("fs") or ""))

    @classmethod
    def _filesystem_from_preview_output(cls, text: str, fallback: str = "") -> str:
        for line in str(text or "").splitlines():
            lowered = line.casefold()
            if "detected" not in lowered and "filesystem target override" not in lowered:
                continue
            for needle, label in (
                ("hfs+", "HFS+"),
                ("hfsx", "HFS+"),
                ("ntfs", "NTFS"),
                ("exfat", "exFAT"),
                ("fat32", "FAT32"),
                ("apfs", "APFS"),
            ):
                if needle in lowered:
                    return label
        return cls._normalize_filesystem_label(fallback)

    def set_mode(self, mode_text: str) -> None:
        mode = str(mode_text).lower()
        if "image only" in mode:
            self._mode = "image-only"
        elif "raw file hunt" in mode or "signature" in mode or mode.startswith("all"):
            self._mode = "signature"
        else:
            self._mode = "filesystem"
        self._refresh_source_plan()

    def _refresh_source_plan(self) -> None:
        if self._source is None:
            return

        if bool(self._source.get("wait_for_new_source")):
            self.locked_label.setText("WAITING SOURCE")
            self.explanation.setText(
                "Start Carv, then connect only the intended source disk. Carv "
                "will keep it unmounted and begin protected imaging automatically."
            )
            self.read_tree.setText("TREE AVAILABLE AFTER SOURCE ARRIVES")
            self.read_tree.setEnabled(False)
            self.tree_state.setText("SOURCE  /  NEW DISK AFTER START")
            self.source_tree.setVisible(False)
            self.safety.setVisible(True)
            return

        media = str(self._source.get("media") or "")
        health = str(self._source.get("health") or "")
        risk = str(self._source.get("risk") or "normal")
        warning = ""
        if "HDD" in media:
            warning = "Rotational media selected. Every preview operation may cost remaining read time."
        if risk == "critical":
            warning = "CRITICAL SMART WARNING. Minimize seeks and consider immediate sequential recovery."
        elif risk == "caution":
            warning = "Drive health is unknown. Treat preview reads as potentially expensive."

        if self._mode in {"signature", "image-only"}:
            image_only = self._mode == "image-only"
            self.locked_label.setText("IMAGE ONLY" if image_only else "RAW FILE HUNT")
            self.explanation.setText(
                f"{warning}\n\n"
                + (
                    "Creates or updates the ddrescue image without recovering files. "
                    "Folder structure and recovery filters are not used."
                    if image_only else
                    "Reads every byte in one forward pass and extracts only the file types selected in Filters. "
                    "Folder structure is not inspected and the source tree stays untouched."
                )
            )
            self.read_tree.setText(
                "TREE BYPASSED FOR IMAGE ONLY"
                if image_only else "TREE BYPASSED FOR SEQUENTIAL CARVE"
            )
            self.read_tree.setEnabled(False)
            self.tree_state.setText(
                "TREE  /  BYPASSED     READ PLAN  /  DDRESCUE IMAGE"
                if image_only else
                "TREE  /  BYPASSED     READ PLAN  /  BYTE-SEQUENTIAL"
            )
            self.source_tree.setVisible(False)
            self.safety.setVisible(True)
        else:
            self.locked_label.setText("TREE NOT READ")
            self.explanation.setText(
                f"{warning}\n\n"
                "Use preview below to read the file tree. This adds extra disk reads. "
                "For badly damaged disks, use Raw File Hunt or create an image first."
            )
            self.read_tree.setText("PREVIEW FILESYSTEM STRUCTURE")
            self.read_tree.setEnabled(not self._tree_loaded)
            self.tree_state.setText("TREE  /  LOADED" if self._tree_loaded else "TREE  /  INACTIVE · 0 READS")
            self.source_tree.setVisible(self._tree_loaded)
            self.safety.setVisible(not self._tree_loaded)

    def _read_source_tree(self) -> None:
        if self._source is None or self._mode != "filesystem":
            return
        if self._preview_thread is not None and self._preview_thread.is_alive():
            return
        self._preview_cancel_event.clear()
        self.read_tree.setEnabled(False)
        self.read_tree.setText("READING · PLEASE WAIT")
        self.locked_label.setText("READING SOURCE STRUCTURE")
        self.locked_label.setStyleSheet(
            f"color: {ACCENT}; background: transparent; font-family: '{mono_font_family()}'; "
            "font-size: 15px; font-weight: 800; letter-spacing: 1.5px;"
        )
        self.explanation.setText(
            "Filesystem metadata is being read from the selected source.\n"
            "A slow or damaged disk may remain at this stage for some time."
        )
        self.preview_progress.setVisible(True)
        self.source_bar.setStyleSheet(
            f"QFrame#sourceBar {{ background: #152019; border: 1px solid {ACCENT}; border-radius: 4px; }}"
        )
        self.source_meta.setText("READING SOURCE…")
        self.tree_state.setText("TREE  /  READING SOURCE METADATA · PLEASE WAIT")
        self._preview_result = None
        source = dict(self._source)
        source["_filesystem"] = self._preview_filesystem_for(source)
        source["_browse_mount_path"] = self._mounted_preview_path(source)
        self._source["_preview_filesystem"] = source["_filesystem"]
        self._source["_browse_mount_path"] = source["_browse_mount_path"]
        initial_filesystem = self._interpreted_filesystem_label()
        self.source_meta.setText(f"FILESYSTEM · {initial_filesystem}  ·  READING TREE…")
        sudo_ok, sudo_error = self._ensure_preview_sudo_lease(source)
        if not sudo_ok:
            self.preview_progress.setVisible(False)
            self.source_bar.setStyleSheet(
                f"QFrame#sourceBar {{ background: #14191e; border: 1px solid {BORDER}; border-radius: 4px; }}"
            )
            self.locked_label.setStyleSheet(
                f"color: {TEXT}; background: transparent; font-family: '{mono_font_family()}'; "
                "font-size: 15px; font-weight: 700; letter-spacing: 1.5px;"
            )
            self.read_tree.setText("PREVIEW FILESYSTEM STRUCTURE")
            self.read_tree.setEnabled(True)
            self.tree_state.setText("TREE  /  PREVIEW PERMISSION NEEDED")
            self._restore_source_meta()
            QMessageBox.warning(self, "Source preview", sudo_error or "Sudo permission was not granted.")
            return
        if self._load_source_tree_from_cache(source):
            return

        def worker() -> None:
            self._preview_result = self._collect_source_folders(source)

        self._preview_thread = threading.Thread(
            target=worker,
            name="carv-folder-preview",
            daemon=True,
        )
        self._preview_thread.start()
        self._preview_timer.start(150)

    def _load_source_tree_from_cache(self, source) -> bool:
        cache_key, signature = self._current_source_cache_identity(source)
        cache = self._load_source_tree_cache()
        entry = cache.get("entries", {}).get(cache_key)
        if not isinstance(entry, dict):
            return False
        if entry.get("signature") != signature:
            return False
        folders = entry.get("root_folders")
        if not isinstance(folders, list):
            return False
        child_cache = {}
        for folder, children in (entry.get("child_folders") or {}).items():
            if isinstance(children, list):
                child_cache[str(folder)] = (list(children), "")
        route = str(entry.get("route") or "metadata")
        filesystem = str(entry.get("filesystem") or source.get("_filesystem") or "")
        mounted_path = str(entry.get("mounted_path") or "")
        self._source_preview_route = "metadata-cache" if route == "metadata" else route
        if filesystem:
            self._source["_interpreted_filesystem"] = filesystem
        if mounted_path:
            self._source["_browse_mount_path"] = mounted_path
        self._child_cache = child_cache
        self._populate_source_tree_root(folders)
        self.preview_progress.setVisible(False)
        self.source_bar.setStyleSheet(
            f"QFrame#sourceBar {{ background: #14191e; border: 1px solid {BORDER}; border-radius: 4px; }}"
        )
        self.locked_label.setStyleSheet(
            f"color: {TEXT}; background: transparent; font-family: '{mono_font_family()}'; "
            "font-size: 15px; font-weight: 700; letter-spacing: 1.5px;"
        )
        self.read_tree.setText("PREVIEW FILESYSTEM STRUCTURE")
        self.read_tree.setEnabled(False)
        self._restore_source_meta()
        self.tree_state.setText(
            f"TREE  /  CACHE HIT · {len(folders):,} ROOT FOLDERS"
        )
        self._child_prefetch_queue = [
            folder for folder in folders if folder not in self._child_cache
        ]
        self._child_prefetch_total = len(folders)
        self._child_prefetch_done = len(folders) - len(self._child_prefetch_queue)
        self._start_next_child_preview()
        return True

    def _save_source_tree_cache(self) -> None:
        if not self._source or not self._tree_loaded:
            return
        # Hypersafe owns persistent state in the run directory.  Do not build a
        # normal source-cache signature here: that signature may inspect the
        # physical source, while all tree reads after bootstrap must use only
        # the sparse image and its ddrescue map.
        if self._source_preview_route == "metadata-hypersafe":
            return
        cache_key, signature = self._current_source_cache_identity(self._source)
        root = self.source_tree.topLevelItem(0)
        root_folders = []
        if root is not None:
            for index in range(root.childCount()):
                folder = str(root.child(index).data(0, Qt.ItemDataRole.UserRole) or "").strip("/")
                if folder and folder != "__carv_placeholder__":
                    root_folders.append(folder)
        cache = self._load_source_tree_cache()
        entries = cache.setdefault("entries", {})
        entries[cache_key] = {
            "signature": signature,
            "saved_at": time.time(),
            "source_path": str(self._source.get("path") or ""),
            "source_name": str(self._source.get("name") or ""),
            "filesystem": self._interpreted_filesystem_label(),
            "route": "metadata" if self._source_preview_route == "metadata-cache" else self._source_preview_route,
            "mounted_path": str(self._source.get("_browse_mount_path") or ""),
            "root_folders": root_folders,
            "child_folders": self._cached_child_map(self._child_cache),
        }
        if len(entries) > 24:
            oldest = sorted(
                entries,
                key=lambda key: float((entries.get(key) or {}).get("saved_at") or 0.0),
            )
            for key in oldest[:len(entries) - 24]:
                entries.pop(key, None)
        self._write_source_tree_cache(cache)

    def _populate_source_tree_root(self, folders) -> None:
        self.source_tree.clear()
        source_name = str(
            (self._source or {}).get("display_name") or
            (self._source or {}).get("name") or
            "Source"
        )
        root = QTreeWidgetItem(self.source_tree, [source_name, "Entire source", "—"])
        root.setData(0, Qt.ItemDataRole.UserRole, "/")
        root.setToolTip(0, "Select this row to recover from the entire filesystem source.")
        for folder in folders:
            item = QTreeWidgetItem(root, [str(folder), "Folder", "—"])
            item.setData(0, Qt.ItemDataRole.UserRole, str(folder))
            self._add_folder_placeholder(item)
        root.setExpanded(True)
        self.source_tree.clearSelection()
        self._tree_loaded = True
        self.safety.setVisible(False)
        self.source_tree.setVisible(True)
        self._update_folder_selection()

    def apply_hypersafe_preview(
        self,
        folders,
        *,
        image_path: str,
        map_path: str,
        status_path: str,
    ) -> None:
        """Install a sparse-image MFT preview without changing normal tree reads."""
        if self._source is None:
            return
        folders = sorted(set(folders), key=str.casefold)
        self._cancel_folder_discovery()
        self._preview_cancel_event.clear()
        self._source["_hypersafe_image_path"] = str(image_path)
        self._source["_hypersafe_map_path"] = str(map_path)
        self._source["_hypersafe_status_path"] = str(status_path)
        self._source["_interpreted_filesystem"] = "NTFS"
        self._source_preview_route = "metadata-hypersafe"
        self._child_cache.clear()
        self._populate_source_tree_root(folders)
        self.preview_progress.setVisible(False)
        self.source_bar.setStyleSheet(
            f"QFrame#sourceBar {{ background: #14191e; border: 1px solid {BORDER}; border-radius: 4px; }}"
        )
        self.read_tree.setText("PREVIEW FILESYSTEM STRUCTURE")
        self.read_tree.setEnabled(False)
        self._child_prefetch_queue.clear()
        self._child_prefetch_total = 0
        self._child_prefetch_done = 0
        self._restore_source_meta()
        self.tree_state.setText(
            f"TREE  /  HYPERSAFE MFT IMAGE · {len(folders):,} ROOT FOLDERS · LAZY CHILDREN"
        )

    def _preview_filesystem_for(self, source) -> str:
        """Keep auto detection unless the operator selects a supported override."""
        window = self.window()
        requested = (
            window.filesystem_combo.currentText().strip().lower()
            if hasattr(window, "filesystem_combo") else "auto detect"
        )
        if requested == "ntfs":
            return "ntfs"
        if requested == "hfs+":
            return "hfsplus"
        interpreted = self._normalize_filesystem_label(
            str(source.get("_interpreted_filesystem") or source.get("fs") or "")
        )
        if interpreted == "NTFS":
            return "ntfs"
        if interpreted == "HFS+":
            return "hfsplus"
        return "auto detect"

    @staticmethod
    def _mounted_preview_path(source) -> str:
        """Prefer the OS's own directory view when the selected device is mounted."""
        source_path = str(source.get("path") or "")
        candidates = [source_path] if os.path.isdir(source_path) else []
        candidates.extend(source.get("mount_paths") or [])
        if source_path.startswith("/dev/"):
            if sys.platform.startswith("linux"):
                try:
                    result = subprocess.run(
                        ["findmnt", "--raw", "--noheadings", "--output", "TARGET", "--source", source_path],
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=4,
                        check=False,
                    )
                    if result.returncode == 0:
                        candidates.extend(result.stdout.splitlines())
                except (OSError, subprocess.SubprocessError):
                    pass
            elif sys.platform == "darwin":
                diskutil_path = source_path.replace("/dev/rdisk", "/dev/disk", 1)
                try:
                    result = subprocess.run(
                        ["diskutil", "info", "-plist", diskutil_path],
                        capture_output=True,
                        timeout=4,
                        check=False,
                    )
                    if result.returncode == 0:
                        mount_path = str(plistlib.loads(result.stdout).get("MountPoint") or "").strip()
                        if mount_path:
                            candidates.append(mount_path)
                except (OSError, subprocess.SubprocessError, ValueError):
                    pass
        for candidate in candidates:
            path = str(candidate or "").strip()
            if path and os.path.isdir(path):
                return path
        return ""

    def _attempt_readonly_partition_mount(self, source) -> str:
        """Let the OS expose a selected partition before asking Carv to parse raw metadata."""
        if not source.get("is_partition"):
            return ""
        source_path = str(source.get("path") or "")
        if not source_path.startswith("/dev/"):
            return ""
        try:
            if sys.platform.startswith("linux"):
                command = [
                    "udisksctl", "mount", "--block-device", source_path,
                    "--options", "ro",
                ]
            elif sys.platform == "darwin":
                command = [
                    "diskutil", "mount", "readOnly",
                    source_path.replace("/dev/rdisk", "/dev/disk", 1),
                ]
            else:
                return ""
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            source["_mount_attempt_error"] = f"Read-only OS mount could not start: {exc}"
            return ""
        if result.returncode != 0:
            detail = self._preview_error_text(
                result.stderr or result.stdout,
                f"exit status {result.returncode}",
            )
            source["_mount_attempt_error"] = f"Read-only OS mount failed: {detail}"
            return ""
        mounted_path = self._mounted_preview_path(source)
        if not mounted_path:
            source["_mount_attempt_error"] = (
                "Read-only OS mount reported success, but no mounted directory was found."
            )
        return mounted_path

    def _collect_source_folders(self, source):
        source_path = str(source.get("path") or "")
        mounted_path = str(source.get("_browse_mount_path") or self._mounted_preview_path(source))
        if not mounted_path:
            mounted_path = self._attempt_readonly_partition_mount(source)
            if mounted_path:
                source["_browse_mount_path"] = mounted_path
        mounted_error = ""
        mount_attempt_error = str(source.get("_mount_attempt_error") or "")
        if mounted_path:
            try:
                return sorted(
                    (entry.name for entry in os.scandir(mounted_path) if entry.is_dir(follow_symlinks=False)),
                    key=str.casefold,
                ), "", "os", mounted_path, self._normalize_filesystem_label(source.get("fs"))
            except OSError as exc:
                mounted_error = f"Could not read mounted source folder: {exc}"

        command = [str(app_runtime_root() / "carv"), "--src", source_path]
        execution_env = self._preview_sudo_environment(self._utf8_preview_environment())
        filesystem = str(source.get("_filesystem") or "auto detect")
        if filesystem in {"ntfs", "hfsplus"}:
            command.extend(["--filesys", filesystem])
        command.append("--list-root-folders")
        if source_path.startswith("/dev/"):
            command = ["sudo", "-n"] + command
        try:
            result = self._run_preview_command(
                command,
                cwd=str(app_runtime_root()),
                env=execution_env,
                timeout=120,
            )
            if result.returncode == 0:
                detected_filesystem = self._filesystem_from_preview_output(
                    f"{result.stderr}\n{result.stdout}",
                    filesystem if filesystem != "auto detect" else source.get("fs", ""),
                )
                folders = sorted(
                    {
                        name.strip("/")
                        for line in result.stdout.splitlines()
                        if (name := self._sanitize_preview_line(line))
                    },
                    key=str.casefold,
                )
                return folders, "", "metadata", "", detected_filesystem
            mft_error = self._preview_error_text(result.stderr or result.stdout, "Folder preview failed.")
            return [], "\n\n".join(detail for detail in (mount_attempt_error, mounted_error, mft_error) if detail), "", "", ""
        except subprocess.TimeoutExpired:
            return [], "\n\n".join(detail for detail in (
                mount_attempt_error,
                mounted_error,
                "Folder preview timed out. The source may be slow, asleep or badly damaged.",
            ) if detail), "", "", ""
        except OSError as exc:
            return [], "\n\n".join(detail for detail in (
                mount_attempt_error,
                mounted_error,
                f"Could not start folder preview: {exc}",
            ) if detail), "", "", ""

    @staticmethod
    def _preview_failure_guidance(error: str) -> str:
        message = str(error or "")
        if "no readable ntfs geometry" not in message.casefold():
            return message
        return (
            f"{message}\n\n"
            "RECOMMENDED NEXT STEP\n"
            "Filesystem metadata is unavailable for this source. Use Raw file hunt, "
            "select the file types needed, and read this selected partition in one forward pass."
        )

    def _poll_source_tree_preview(self) -> None:
        if self._preview_cancel_event.is_set():
            self._preview_timer.stop()
            self._preview_result = None
            return
        if self._preview_thread is not None and self._preview_thread.is_alive():
            return
        self._preview_timer.stop()
        self._preview_thread = None
        folders, error, route, mounted_path, filesystem = self._preview_result or (
            [], "Folder preview returned no result.", "", "", ""
        )
        self._preview_result = None
        self.preview_progress.setVisible(False)
        self.source_bar.setStyleSheet(
            f"QFrame#sourceBar {{ background: #14191e; border: 1px solid {BORDER}; border-radius: 4px; }}"
        )
        if self._source:
            self._source_preview_route = route if not error else ""
            if filesystem:
                self._source["_interpreted_filesystem"] = filesystem
            if mounted_path:
                self._source["_browse_mount_path"] = mounted_path
            self._restore_source_meta()
        self.locked_label.setStyleSheet(
            f"color: {TEXT}; background: transparent; font-family: '{mono_font_family()}'; "
            "font-size: 15px; font-weight: 700; letter-spacing: 1.5px;"
        )
        self.read_tree.setText("PREVIEW FILESYSTEM STRUCTURE")
        self.read_tree.setEnabled(True)
        if error:
            self.tree_state.setText("TREE  /  PREVIEW FAILED")
            self._refresh_source_plan()
            QMessageBox.warning(self, "Source preview", self._preview_failure_guidance(error))
            return
        self._populate_source_tree_root(folders)
        self.tree_state.setText("CTRL / ⌘ CLICK  /  MULTISELECT     SHIFT CLICK  /  RANGE")
        self._child_prefetch_queue = list(folders)
        self._child_prefetch_total = len(folders)
        self._child_prefetch_done = 0
        self._save_source_tree_cache()
        self._start_next_child_preview()

    @staticmethod
    def _add_folder_placeholder(item: QTreeWidgetItem) -> None:
        placeholder = QTreeWidgetItem(["Loading available on expand…", "", ""])
        placeholder.setData(0, Qt.ItemDataRole.UserRole, "__carv_placeholder__")
        placeholder.setFlags(placeholder.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        item.addChild(placeholder)

    def _load_child_folders(self, item: QTreeWidgetItem) -> None:
        folder = str(item.data(0, Qt.ItemDataRole.UserRole) or "")
        if not folder or folder == "__carv_placeholder__" or item.childCount() != 1:
            return
        placeholder_kind = str(item.child(0).data(0, Qt.ItemDataRole.UserRole) or "")
        if placeholder_kind not in {"__carv_placeholder__", "__carv_retry__"}:
            return
        if placeholder_kind == "__carv_retry__":
            self._child_cache.pop(folder, None)
        if folder in self._child_cache:
            children, error = self._child_cache[folder]
            self._populate_child_item(item, folder, children, error)
            return
        source = dict(self._source or {})
        if self._source_preview_needs_sudo(source):
            sudo_ok, sudo_error = self._ensure_preview_sudo_lease(source)
            if not sudo_ok:
                self._populate_child_item(
                    item,
                    folder,
                    [],
                    sudo_error or "Sudo permission is needed before reading this branch from disk.",
                )
                return
        item.child(0).setText(0, "Reading child folders…")
        if self._child_preview_thread is not None and self._child_preview_thread.is_alive():
            if folder != self._child_preview_folder:
                self._child_prefetch_queue = [
                    queued for queued in self._child_prefetch_queue if queued != folder
                ]
                self._child_prefetch_queue.insert(0, folder)
                item.child(0).setText(0, "Next to load…")
            return
        self._child_prefetch_queue = [
            queued for queued in self._child_prefetch_queue if queued != folder
        ]
        self._child_prefetch_queue.insert(0, folder)
        self._start_next_child_preview()

    def _source_tree_item_for_path(self, folder: str) -> QTreeWidgetItem | None:
        root = self.source_tree.topLevelItem(0)
        if root is None:
            return None
        pending = [root]
        while pending:
            item = pending.pop()
            if str(item.data(0, Qt.ItemDataRole.UserRole) or "") == folder:
                return item
            pending.extend(item.child(index) for index in range(item.childCount()))
        return None

    def _start_next_child_preview(self) -> None:
        if self._preview_cancel_event.is_set():
            self._child_prefetch_queue.clear()
            self._stop_prefetch_activity()
            return
        if self._child_preview_thread is not None and self._child_preview_thread.is_alive():
            return
        while self._child_prefetch_queue:
            folder = self._child_prefetch_queue.pop(0)
            if folder not in self._child_cache:
                break
        else:
            self._child_preview_folder = ""
            self._stop_prefetch_activity()
            self._restore_source_meta()
            return

        self._child_preview_folder = folder
        self._child_preview_item = self._source_tree_item_for_path(folder)
        self._child_preview_result = None
        source = dict(self._source or {})
        generation = self._source_generation
        source["_filesystem"] = self._preview_filesystem_for(source)
        if self._source_preview_needs_sudo(source) and not self._setup_sudo_ready:
            self._child_preview_folder = ""
            self._child_preview_item = None
            self._stop_prefetch_activity()
            self._restore_source_meta()
            return

        def worker() -> None:
            children, error = self._collect_child_folders(source, folder)
            self._child_preview_result = generation, folder, children, error

        self._child_preview_thread = threading.Thread(
            target=worker, name="carv-folder-prefetch", daemon=True
        )
        self._child_preview_thread.start()
        self._child_preview_timer.start(150)
        self._start_prefetch_activity()

    def _collect_child_folders(self, source, folder: str):
        hypersafe_image = str(source.get("_hypersafe_image_path") or "")
        hypersafe_status = str(source.get("_hypersafe_status_path") or "")
        source_path = hypersafe_image or str(source.get("path") or "")
        mounted_path = "" if hypersafe_image else str(
            source.get("_browse_mount_path") or self._mounted_preview_path(source)
        )
        mounted_error = ""
        if mounted_path:
            target = Path(mounted_path) / folder
            try:
                children = sorted(
                    (entry.name for entry in os.scandir(target) if entry.is_dir(follow_symlinks=False)),
                    key=str.casefold,
                )
                return children, ""
            except OSError as exc:
                mounted_error = f"Could not read mounted folder {folder}: {exc}"
        command = [str(app_runtime_root() / "carv"), "--src", source_path]
        filesystem = "ntfs" if hypersafe_image else str(source.get("_filesystem") or "")
        if filesystem in {"ntfs", "hfsplus"}:
            command.extend(["--filesys", filesystem])
        command.extend(["--list-folders-under", folder])
        if hypersafe_image and hypersafe_status:
            command.extend(["--hypersafe-preview-status", hypersafe_status])
        env = self._preview_sudo_environment(self._utf8_preview_environment())
        if source_path.startswith("/dev/") and not hypersafe_image:
            command = ["sudo", "-n"] + command
        try:
            result = self._run_preview_command(
                command,
                cwd=str(app_runtime_root()),
                env=env,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return [], mounted_error or f"Child preview for {folder} timed out."
        except OSError as exc:
            return [], mounted_error or f"Could not start child preview: {exc}"
        if result.returncode != 0:
            return [], mounted_error or self._preview_error_text(
                result.stderr or result.stdout,
                "Child preview failed.",
            )
        children = []
        prefix = folder.strip("/") + "/"
        for line in result.stdout.splitlines():
            value = self._sanitize_preview_line(line).strip("/")
            if not value:
                continue
            if value.startswith(prefix):
                value = value[len(prefix):]
            if "/" not in value and value not in children:
                children.append(value)
        return sorted(children, key=str.casefold), ""

    def _poll_child_folder_preview(self) -> None:
        if self._preview_cancel_event.is_set():
            self._child_preview_timer.stop()
            self._child_preview_result = None
            self._child_preview_item = None
            return
        if self._child_preview_thread is not None and self._child_preview_thread.is_alive():
            return
        self._child_preview_timer.stop()
        self._child_preview_thread = None
        item = self._child_preview_item
        self._child_preview_item = None
        result = self._child_preview_result
        self._child_preview_result = None
        if result is None:
            self._start_next_child_preview()
            return
        generation, folder, children, error = result
        if generation != self._source_generation:
            self._start_next_child_preview()
            return
        self._child_prefetch_done += 1
        if not error:
            self._child_cache[folder] = (list(children), "")
            self._save_source_tree_cache()
        item = item or self._source_tree_item_for_path(folder)
        if item is not None:
            self._populate_child_item(item, folder, children, error)
        self._start_next_child_preview()

    def _run_preview_command(self, command, *, cwd: str, env: dict, timeout: int):
        if self._preview_cancel_event.is_set():
            return subprocess.CompletedProcess(command, 130, "", "Folder preview cancelled.")

        def run_once(parts, environment):
            popen_kwargs = {
                "cwd": cwd,
                "env": environment,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
                "encoding": "utf-8",
                "errors": "replace",
            }
            if os.name == "posix":
                popen_kwargs["process_group"] = 0
            try:
                process = subprocess.Popen(parts, **popen_kwargs)
            except TypeError:
                popen_kwargs.pop("process_group", None)
                if os.name == "posix":
                    popen_kwargs["start_new_session"] = True
                process = subprocess.Popen(parts, **popen_kwargs)
            with self._preview_process_lock:
                self._preview_process = process
            if self._preview_cancel_event.is_set():
                self._terminate_preview_process(process)
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._terminate_preview_process(process)
                process.communicate()
                raise
            finally:
                with self._preview_process_lock:
                    if self._preview_process is process:
                        self._preview_process = None
            return subprocess.CompletedProcess(parts, process.returncode, stdout, stderr)

        result = run_once(command, env)
        if (
            result.returncode != 0
            and len(command) >= 3
            and command[0:2] == ["sudo", "-n"]
            and sudo_auth_failed_text(f"{result.stderr}\n{result.stdout}")
            and not self._preview_cancel_event.is_set()
        ):
            self._setup_sudo_ready = False
            self._setup_sudo_environment = None
            ok, retry_env, error = ensure_sudo_credential(
                "Preview filesystem structure",
                "Carv needs permission to read folder metadata from this source.",
                "Read source",
                cwd=cwd,
                noninteractive=False,
            )
            if not ok:
                return subprocess.CompletedProcess(
                    command,
                    result.returncode,
                    result.stdout,
                    error or "Sudo permission expired during folder preview.",
                )
            self._setup_sudo_ready = True
            self._setup_sudo_environment = retry_env
            if not self._sudo_keepalive_timer.isActive():
                self._sudo_keepalive_timer.start()
            retry_command = ["sudo", "-A"] + command[2:]
            result = run_once(retry_command, retry_env)
        return result

    @staticmethod
    def _terminate_preview_process(process) -> None:
        if process is None or process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            else:
                process.terminate()
        except (OSError, ProcessLookupError):
            pass

    def _cancel_folder_discovery(self) -> None:
        self._preview_cancel_event.set()
        self._source_generation += 1
        self._child_prefetch_queue.clear()
        self._preview_timer.stop()
        self._child_preview_timer.stop()
        self._stop_prefetch_activity()
        self._preview_result = None
        self._child_preview_result = None
        self._child_preview_item = None
        with self._preview_process_lock:
            process = self._preview_process
        self._terminate_preview_process(process)

    def stop_folder_discovery_for_recovery(self) -> None:
        """Stop preview I/O while preserving the operator's selected folder scope."""
        self._cancel_folder_discovery()
        self.preview_progress.setVisible(False)
        self.read_tree.setEnabled(False)
        self._restore_source_meta()

    def shutdown(self) -> None:
        """Stop background source work before Qt destroys this panel."""
        self._sudo_keepalive_timer.stop()
        self._cancel_folder_discovery()
        self._setup_sudo_ready = False
        self._setup_sudo_environment = None

        deadline = time.monotonic() + 0.4
        threads = (self._preview_thread, self._child_preview_thread)
        for thread in threads:
            if thread is None or not thread.is_alive():
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            thread.join(timeout=remaining)

    def _populate_child_item(
        self,
        item: QTreeWidgetItem,
        folder: str,
        children,
        error: str,
    ) -> None:
        item.takeChildren()
        if error:
            failed = QTreeWidgetItem(["Preview failed · collapse and expand to retry", "", ""])
            failed.setData(0, Qt.ItemDataRole.UserRole, "__carv_retry__")
            failed.setFlags(failed.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            failed.setToolTip(0, error)
            item.addChild(failed)
            return
        parent_path = folder.strip("/")
        for child_name in children:
            child_path = f"{parent_path}/{child_name}" if parent_path else child_name
            child = QTreeWidgetItem([child_name, "Folder", "—"])
            child.setData(0, Qt.ItemDataRole.UserRole, child_path)
            self._add_folder_placeholder(child)
            item.addChild(child)
        if not children:
            label = (
                "No child folders"
                if self._source_preview_route == "os"
                else "No child folders reported by metadata preview"
            )
            empty = QTreeWidgetItem([label, "", ""])
            empty.setFlags(empty.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            item.addChild(empty)

    def _update_folder_selection(self) -> None:
        if not self._tree_loaded:
            return
        selected = [
            str(item.data(0, Qt.ItemDataRole.UserRole) or item.text(0))
            for item in self.source_tree.selectedItems()
        ]
        count = len(selected)
        self.tree_state.setText(
            f"FOLDER FILTER  /  {count} SELECTED     CTRL / ⌘ CLICK TO ADJUST"
            if count
            else "FOLDER FILTER  /  NONE SELECTED"
        )
        if self._folder_selection_callback is not None:
            self._folder_selection_callback(selected)


class OutputTreePanel(QFrame):
    """Browse real local and mounted output locations without touching the source."""

    def __init__(self, output_changed_callback=None, configured_default: str = "") -> None:
        super().__init__()
        self._output_changed_callback = output_changed_callback
        self._service_id = ""
        self._selected_output_path = ""
        self._updating_output_tree = False
        self._handling_output_selection = False
        self._refreshing_output_roots = False
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        box = group_box("03  /  OUTPUT")
        layout = QVBoxLayout(box)
        layout.setContentsMargins(12, 16, 12, 12)
        layout.setSpacing(8)

        location_bar = QFrame()
        location_bar.setObjectName("locationBar")
        location_bar.setStyleSheet(
            f"QFrame#locationBar {{ background: #14191e; border: 1px solid {BORDER}; border-radius: 4px; }}"
        )
        location_row = QHBoxLayout(location_bar)
        location_row.setContentsMargins(9, 6, 9, 6)
        self.path_label = QLabel("SELECT A DESTINATION FOLDER")
        self.path_label.setStyleSheet(f"color: {MUTED}; background: transparent; font-family: '{mono_font_family()}'; font-size: 11px;")
        self.volume_combo = TechnicalComboBox()
        self._output_roots = self._available_output_roots()
        for path, label in self._output_roots:
            self.volume_combo.addItem(label, path)
        self.volume_combo.setMaximumWidth(230)
        self.volume_combo.installEventFilter(self)
        location_row.addWidget(self.path_label)
        location_row.addStretch(1)
        location_row.addWidget(self.volume_combo)
        layout.addWidget(location_bar)

        browse_row = QHBoxLayout()
        browse_row.addStretch(1)
        browse_button = QPushButton("BROWSE OUTPUT FOLDER…")
        browse_button.clicked.connect(self._browse_output_folder)
        browse_row.addWidget(browse_button)
        layout.addLayout(browse_row)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["NAME", "TYPE", "MODIFIED"])
        self.tree.setRootIsDecorated(True)
        self.tree.setIndentation(17)
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tree.itemSelectionChanged.connect(self._output_selection_changed)
        self.tree.itemExpanded.connect(self._load_output_children)
        self.tree.setColumnWidth(0, 230)
        self.tree.setColumnWidth(1, 100)
        self._populate_volume(0)
        self.volume_combo.currentIndexChanged.connect(self._volume_selection_changed)

        layout.addWidget(self.tree, 1)

        self.remember_output = QCheckBox("Remember selected folder as preferred output")
        self.remember_output.setChecked(True)
        self.remember_output.setToolTip(
            "When enabled, Carv asks before saving this folder to the local config as the default for future jobs."
        )
        layout.addWidget(self.remember_output)

        self.run_folder_notice = QLabel()
        self.run_folder_notice.setWordWrap(True)
        self.run_folder_notice.setStyleSheet(
            "color: #f0c36a; background: #302819; border: 1px solid #6b5528; "
            "border-radius: 4px; padding: 6px 8px; font-size: 10px; font-weight: 700;"
        )
        self.run_folder_notice.setToolTip(
            "Existing run folders are allowed. Start Recovery will ask whether to resume/reuse the run or archive it and restart clean."
        )
        self.run_folder_notice.hide()
        layout.addWidget(self.run_folder_notice)

        outer.addWidget(box)
        if configured_default:
            self._apply_output_path(configured_default)

    def eventFilter(self, watched, event) -> bool:
        if watched is getattr(self, "volume_combo", None) and event is not None:
            if event.type() in {
                QEvent.Type.MouseButtonPress,
                QEvent.Type.FocusIn,
                QEvent.Type.Show,
            }:
                self._refresh_output_roots()
        return super().eventFilter(watched, event)

    def _browse_output_folder(self) -> None:
        current = self._selected_output_path or self.path_label.text().strip()
        if not os.path.isdir(current):
            current = str(Path.home())
        dialog = QFileDialog(self, "Choose Output Folder", current)
        dialog.setFileMode(QFileDialog.FileMode.Directory)
        dialog.setOption(QFileDialog.Option.ShowDirsOnly, True)
        if sys.platform == "darwin":
            # Qt's native Cocoa dialog can crash if it is opened immediately
            # after a QTreeWidget current-item transition. Keep this dialog in
            # Qt on macOS; Ubuntu can continue to use its native picker.
            dialog.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        if dialog.exec():
            selected = dialog.selectedFiles()
            if selected:
                self._apply_output_path(selected[0])

    def _apply_output_path(self, path: str) -> None:
        normalized = str(Path(path).expanduser().resolve())
        _tested, writable, _detail = self._test_destination_writable(normalized)
        self.path_label.setText(normalized)
        self.path_label.setStyleSheet(
            f"color: {TEXT}; background: transparent; font-family: '{mono_font_family()}'; font-size: 11px;"
        )
        self._selected_output_path = normalized
        root_index = self._output_root_index_for_path(normalized)
        if root_index is None:
            self._output_roots.append((normalized, f"CUSTOM · {normalized}"))
            self.volume_combo.addItem(f"CUSTOM · {Path(normalized).name or normalized}", normalized)
            root_index = self.volume_combo.count() - 1
        combo_was_blocked = self.volume_combo.blockSignals(True)
        try:
            self.volume_combo.setCurrentIndex(root_index)
        finally:
            self.volume_combo.blockSignals(combo_was_blocked)
        self._populate_volume(root_index)
        self.path_label.setText(normalized)
        self.path_label.setStyleSheet(
            f"color: {TEXT}; background: transparent; font-family: '{mono_font_family()}'; font-size: 11px;"
        )
        item = self._reveal_output_path(normalized)
        if item is not None:
            signals_were_blocked = self.tree.blockSignals(True)
            try:
                self.tree.clearSelection()
                self.tree.setCurrentItem(item)
                item.setSelected(True)
                self.tree.scrollToItem(item)
            finally:
                self.tree.blockSignals(signals_were_blocked)
        self._selected_output_path = normalized
        self._show_planned_service_folder()
        if self._output_changed_callback is not None:
            self._output_changed_callback(normalized, writable)

    def set_service_id(self, service_id: str) -> None:
        self._service_id = str(service_id or "").strip()
        self._show_planned_service_folder()

    @staticmethod
    def _planned_service_role() -> int:
        return int(getattr(Qt.ItemDataRole.UserRole, "value", Qt.ItemDataRole.UserRole)) + 1

    @staticmethod
    def _output_loaded_role() -> int:
        return int(getattr(Qt.ItemDataRole.UserRole, "value", Qt.ItemDataRole.UserRole)) + 2

    @staticmethod
    def _output_placeholder_role() -> int:
        return int(getattr(Qt.ItemDataRole.UserRole, "value", Qt.ItemDataRole.UserRole)) + 3

    @staticmethod
    def _safe_output_path_text(value) -> str:
        if value is None:
            return ""
        try:
            text = value if isinstance(value, str) else os.fsdecode(value)
        except (OSError, TypeError, ValueError, RuntimeError, RecursionError):
            return ""
        text = str(text or "").strip()
        if not text or "\x00" in text:
            return ""
        try:
            return os.path.normpath(os.path.expanduser(text))
        except (OSError, TypeError, ValueError, RuntimeError, RecursionError):
            return ""

    @staticmethod
    def _path_is_directory(path: str) -> bool:
        path = OutputTreePanel._safe_output_path_text(path)
        if not path:
            return False
        try:
            return os.path.isdir(path)
        except (OSError, TypeError, ValueError, RuntimeError, RecursionError):
            return False

    def _new_output_folder_item(self, path: str, type_text: str = "Folder") -> QTreeWidgetItem:
        folder_path = Path(path)
        try:
            modified = datetime.fromtimestamp(folder_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        except OSError:
            modified = "—"
        item = QTreeWidgetItem([folder_path.name or str(folder_path), type_text, modified])
        item.setData(0, Qt.ItemDataRole.UserRole, str(folder_path))
        item.setData(0, self._output_loaded_role(), False)
        placeholder = QTreeWidgetItem(["Expand to browse…", "", ""])
        placeholder.setData(0, self._output_placeholder_role(), True)
        placeholder.setFlags(placeholder.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        item.addChild(placeholder)
        return item

    def _load_output_children(self, item: QTreeWidgetItem) -> None:
        if item.data(0, self._output_loaded_role()) is True:
            return
        path = self._safe_output_path_text(item.data(0, Qt.ItemDataRole.UserRole))
        if not path or not os.path.isdir(path):
            return
        for index in range(item.childCount() - 1, -1, -1):
            if item.child(index).data(0, self._output_placeholder_role()):
                removed = item.takeChild(index)
                del removed
        try:
            entries = sorted(
                (
                    entry for entry in os.scandir(path)
                    if not entry.name.startswith(".") and entry.is_dir(follow_symlinks=False)
                ),
                key=lambda entry: entry.name.casefold(),
            )
        except OSError:
            entries = []
        existing_paths = {
            self._safe_output_path_text(item.child(index).data(0, Qt.ItemDataRole.UserRole))
            for index in range(item.childCount())
        }
        for entry in entries:
            if entry.path not in existing_paths:
                item.addChild(self._new_output_folder_item(entry.path))
        item.setData(0, self._output_loaded_role(), True)
        if not self._updating_output_tree:
            self._show_planned_service_folder()

    def _output_root_index_for_path(self, path: str) -> int | None:
        path = self._safe_output_path_text(path)
        if not path:
            return None
        wanted = os.path.normcase(os.path.normpath(path))
        matches = []
        for index, (root, _label) in enumerate(self._output_roots):
            root = self._safe_output_path_text(root)
            if not root:
                continue
            candidate = os.path.normcase(os.path.normpath(root))
            try:
                if os.path.commonpath((wanted, candidate)) == candidate:
                    matches.append((len(candidate), index))
            except ValueError:
                continue
        return max(matches)[1] if matches else None

    def _reveal_output_path(self, path: str) -> QTreeWidgetItem | None:
        root = self.tree.topLevelItem(0)
        if root is None:
            return None
        path = self._safe_output_path_text(path)
        root_path = self._safe_output_path_text(root.data(0, Qt.ItemDataRole.UserRole))
        if not path or not root_path:
            return None
        try:
            relative = Path(path).relative_to(Path(root_path))
        except (TypeError, ValueError, RuntimeError, RecursionError):
            return None
        current = root
        for part in relative.parts:
            self._load_output_children(current)
            current_path = self._safe_output_path_text(current.data(0, Qt.ItemDataRole.UserRole))
            if not current_path:
                return None
            wanted = os.path.normcase(os.path.normpath(os.path.join(current_path, part)))
            child = next((
                current.child(index)
                for index in range(current.childCount())
                if os.path.normcase(os.path.normpath(
                    self._safe_output_path_text(current.child(index).data(0, Qt.ItemDataRole.UserRole))
                )) == wanted
            ), None)
            if child is None:
                return None
            current.setExpanded(True)
            current = child
        return current

    def _find_output_item_by_path(self, path: str):
        path = self._safe_output_path_text(path)
        if not path:
            return None
        wanted = os.path.normcase(os.path.normpath(path))

        def find_below(parent: QTreeWidgetItem):
            item_path = self._safe_output_path_text(parent.data(0, Qt.ItemDataRole.UserRole))
            if item_path and os.path.normcase(os.path.normpath(item_path)) == wanted:
                return parent
            for child_index in range(parent.childCount()):
                found = find_below(parent.child(child_index))
                if found is not None:
                    return found
            return None

        for top_index in range(self.tree.topLevelItemCount()):
            found = find_below(self.tree.topLevelItem(top_index))
            if found is not None:
                return found
        return None

    def _restore_output_selection(self) -> None:
        item = self._find_output_item_by_path(self._selected_output_path)
        if item is None:
            return
        signals_were_blocked = self.tree.blockSignals(True)
        try:
            self.tree.clearSelection()
            self.tree.setCurrentItem(item)
            item.setSelected(True)
        finally:
            self.tree.blockSignals(signals_were_blocked)

    def _show_planned_service_folder(self) -> None:
        if self._updating_output_tree:
            return
        self._update_run_folder_notice()
        planned_role = self._planned_service_role()

        def item_row_and_parent_index(item: QTreeWidgetItem):
            item_parent = item.parent()
            if item_parent is None:
                return self.tree.indexOfTopLevelItem(item), self.tree.rootIndex()
            return item_parent.indexOfChild(item), self.tree.indexFromItem(item_parent)

        def clear_existing_style(item: QTreeWidgetItem) -> None:
            row, parent_index = item_row_and_parent_index(item)
            self.tree.removeItemWidget(item, 0)
            if row >= 0:
                self.tree.setFirstColumnSpanned(row, parent_index, False)
            item.setData(0, planned_role, None)
            item.setText(1, "Folder")
            for column in range(3):
                item.setForeground(column, QBrush(QColor(TEXT)))
                item.setBackground(column, QBrush())

        def install_run_row(
            item: QTreeWidgetItem,
            *,
            status: str,
            timing: str,
            background: str,
            tooltip: str,
            italic_name: bool,
        ) -> None:
            row, parent_index = item_row_and_parent_index(item)
            if row < 0:
                return
            self.tree.setFirstColumnSpanned(row, parent_index, True)
            run_row = QFrame()
            run_row.setToolTip(tooltip)
            run_row.setStyleSheet(
                f"QFrame {{ background: {background}; border: none; "
                "border-top: 1px solid #365846; border-bottom: 1px solid #365846; } "
                "QLabel { background: transparent; border: none; padding: 0; }"
            )
            run_layout = QHBoxLayout(run_row)
            run_layout.setContentsMargins(8, 0, 8, 0)
            run_layout.setSpacing(18)
            name_label = QLabel(item.text(0))
            name_label.setStyleSheet(
                f"color: {ACCENT}; font-weight: 800; "
                f"font-style: {'italic' if italic_name else 'normal'};"
            )
            status_label = QLabel(status)
            status_label.setStyleSheet(f"color: {ACCENT}; font-weight: 600;")
            timing_label = QLabel(timing)
            timing_label.setStyleSheet("color: #a8c8b7; font-weight: 600;")
            run_layout.addWidget(name_label, 3)
            run_layout.addWidget(status_label, 2)
            run_layout.addWidget(timing_label, 2)
            self.tree.setItemWidget(item, 0, run_row)
            item.setToolTip(0, tooltip)

        # Never remove the item Qt currently considers active. A non-selectable
        # tree item can still become current on some Qt/macOS combinations.
        current = self.tree.currentItem()
        if current is not None and current.data(0, planned_role) == "planned-service-folder":
            self._restore_output_selection()

        def remove_planned(parent: QTreeWidgetItem) -> None:
            for index in range(parent.childCount() - 1, -1, -1):
                child = parent.child(index)
                if child.data(0, planned_role) == "planned-service-folder":
                    removed = parent.takeChild(index)
                    del removed
                else:
                    if child.data(0, planned_role) == "existing-service-folder":
                        clear_existing_style(child)
                    remove_planned(child)

        for index in range(self.tree.topLevelItemCount()):
            remove_planned(self.tree.topLevelItem(index))
        parent = self._find_output_item_by_path(self._selected_output_path)
        if parent is None or not self._service_id:
            return
        if parent.data(0, planned_role) == "existing-service-folder":
            clear_existing_style(parent)
            parent.setText(1, "Selected folder")
        parent_path = self._safe_output_path_text(parent.data(0, Qt.ItemDataRole.UserRole))
        if parent_path and os.path.basename(parent_path.rstrip(os.sep)) == self._service_id:
            parent.setData(0, planned_role, "existing-service-folder")
            parent.setText(1, "Existing Service ID folder")
            install_run_row(
                parent,
                status="Existing Service ID folder",
                timing="Reuse on start",
                background="#294536",
                tooltip="This selected output folder already has the Service ID name; Carv will reuse it as the run folder.",
                italic_name=False,
            )
            return
        for index in range(parent.childCount()):
            child = parent.child(index)
            if child.text(0) == self._service_id:
                if index != 0:
                    child = parent.takeChild(index)
                    parent.insertChild(0, child)
                child.setData(0, planned_role, "existing-service-folder")
                child.setText(1, "Existing Service ID folder")
                install_run_row(
                    child,
                    status="Existing Service ID folder",
                    timing="Reuse on start",
                    background="#294536",
                    tooltip="This Service ID folder already exists. Carv will reuse it for this run.",
                    italic_name=False,
                )
                parent.setExpanded(True)
                return
        planned = QTreeWidgetItem([self._service_id, "Planned · created by Carv", "On start"])
        planned.setData(0, planned_role, "planned-service-folder")
        planned.setFlags(
            planned.flags()
            & ~Qt.ItemFlag.ItemIsSelectable
        )
        planned.setForeground(0, QBrush(QColor(ACCENT)))
        planned.setForeground(1, QBrush(QColor(ACCENT)))
        planned.setForeground(2, QBrush(QColor("#78a58e")))
        planned_background = QBrush(QColor("#20372b"))
        for column in range(3):
            planned.setBackground(column, planned_background)
        planned.setToolTip(0, "Preview only. Carv creates this Service ID folder when the run starts.")
        planned_font = planned.font(0)
        planned_font.setItalic(True)
        planned_font.setBold(True)
        planned.setFont(0, planned_font)
        parent.insertChild(0, planned)
        install_run_row(
            planned,
            status="Planned · created by Carv",
            timing="On start",
            background="#20372b",
            tooltip="Preview only. Carv creates this Service ID folder when the run starts.",
            italic_name=True,
        )
        parent.setExpanded(True)

    def _update_run_folder_notice(self) -> None:
        if not hasattr(self, "run_folder_notice"):
            return
        output = self._safe_output_path_text(self._selected_output_path)
        service_id = str(self._service_id or "").strip()
        if not output or not service_id:
            self.run_folder_notice.hide()
            return
        if not output or "/" in service_id or "\\" in service_id or "\x00" in service_id:
            self.run_folder_notice.hide()
            return
        output_leaf = os.path.basename(output.rstrip(os.sep))
        run_path = output if output_leaf == service_id else os.path.join(output, service_id)
        try:
            run_is_dir = os.path.isdir(run_path)
            run_exists = os.path.exists(run_path)
        except (OSError, TypeError, ValueError, RuntimeError, RecursionError):
            self.run_folder_notice.hide()
            return
        if run_is_dir:
            self.run_folder_notice.setText(
                f"ⓘ RUN FOLDER ALREADY EXISTS · REUSE IS ALLOWED\n{run_path}"
            )
            self.run_folder_notice.show()
            return
        if run_exists:
            self.run_folder_notice.setText(
                f"⚠ RUN PATH ALREADY EXISTS AND IS NOT A FOLDER\n{run_path}"
            )
            self.run_folder_notice.show()
            return
        self.run_folder_notice.hide()

    @staticmethod
    def _test_destination_writable(path: str):
        path = OutputTreePanel._safe_output_path_text(path)
        if not path or not OutputTreePanel._path_is_directory(path):
            return False, False, "folder unavailable"
        test_path = os.path.join(path, f".carv-write-test-{os.getpid()}-{time.time_ns()}")
        descriptor = None
        try:
            descriptor = os.open(
                test_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.write(descriptor, b"carv destination write test\n")
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.unlink(test_path)
            return True, True, "write + fsync + delete"
        except OSError as exc:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                if os.path.exists(test_path):
                    os.unlink(test_path)
            except OSError:
                pass
            return True, False, exc.strerror or exc.__class__.__name__

    def _refresh_output_roots(self) -> None:
        if self._refreshing_output_roots or not hasattr(self, "volume_combo"):
            return
        self._refreshing_output_roots = True
        blocked = self.volume_combo.blockSignals(True)
        try:
            current_root = self._safe_output_path_text(self.volume_combo.currentData())
            selected = self._safe_output_path_text(self._selected_output_path)
            roots = self._available_output_roots()
            if selected and not any(
                self._safe_output_path_text(path) == selected for path, _label in roots
            ):
                roots.append((selected, f"CUSTOM · {Path(selected).name or selected}"))
            self._output_roots = roots
            self.volume_combo.clear()
            for path, label in self._output_roots:
                self.volume_combo.addItem(label, path)
            target = current_root or selected
            index = self._output_root_index_for_path(target) if target else 0
            if index is not None and 0 <= index < self.volume_combo.count():
                self.volume_combo.setCurrentIndex(index)
        finally:
            self.volume_combo.blockSignals(blocked)
            self._refreshing_output_roots = False

    def _populate_volume(self, index: int) -> None:
        if not hasattr(self, "tree"):
            return
        if not self._refreshing_output_roots:
            self._refresh_output_roots()
            index = self.volume_combo.currentIndex()
        self._updating_output_tree = True
        signals_were_blocked = self.tree.blockSignals(True)
        try:
            self.tree.clear()
            self._selected_output_path = ""
            self.path_label.setText("SELECT A DESTINATION FOLDER")
            self.path_label.setStyleSheet(
                f"color: {MUTED}; background: transparent; font-family: '{mono_font_family()}'; font-size: 11px;"
            )

            root_path = self._safe_output_path_text(self.volume_combo.itemData(index))
            if not root_path or not self._path_is_directory(root_path):
                return
            root = self._new_output_folder_item(root_path, "Volume")
            self.tree.addTopLevelItem(root)
            self._load_output_children(root)
            root.setExpanded(True)
            self.tree.clearSelection()
        finally:
            self.tree.blockSignals(signals_were_blocked)
            self._updating_output_tree = False
        if self._output_changed_callback is not None:
            self._output_changed_callback("", False)

    def _volume_selection_changed(self, index: int) -> None:
        """Make an explicit dropdown choice the active output destination."""
        if self._refreshing_output_roots or index < 0:
            return
        root_path = self._safe_output_path_text(self.volume_combo.itemData(index))
        if not root_path or not self._path_is_directory(root_path):
            return
        self._apply_output_path(root_path)

    def _output_selection_changed(self) -> None:
        if self._updating_output_tree or self._handling_output_selection:
            return
        self._handling_output_selection = True
        try:
            item = self.tree.currentItem()
            planned_role = self._planned_service_role()
            selected_path = (
                self._safe_output_path_text(item.data(0, Qt.ItemDataRole.UserRole))
                if item is not None and item.data(0, planned_role) != "planned-service-folder"
                else ""
            )
            is_folder = bool(selected_path and self._path_is_directory(selected_path))
            if not is_folder:
                # Decorative/planned rows are not real output choices. Keep the
                # previous destination logically, but avoid selection recursion.
                return
            self.path_label.setText(selected_path)
            self.path_label.setStyleSheet(
                f"color: {TEXT}; background: transparent; font-family: '{mono_font_family()}'; font-size: 11px;"
            )
            _tested, writable, _detail = self._test_destination_writable(selected_path)
            self._selected_output_path = selected_path
            self._show_planned_service_folder()
            if self._output_changed_callback is not None:
                self._output_changed_callback(selected_path, writable)
        finally:
            self._handling_output_selection = False

    def _available_output_roots(self):
        roots = []
        seen = set()

        def add(path: Path, kind: str) -> None:
            try:
                resolved = str(path.expanduser().resolve())
            except OSError:
                return
            if resolved in seen or not os.path.isdir(resolved):
                return
            seen.add(resolved)
            try:
                stat = os.statvfs(resolved)
                free = stat.f_bavail * stat.f_frsize
                free_text = SourcePickerDialog._human_bytes(free)
            except OSError:
                free_text = "free space unknown"
            roots.append((resolved, f"{kind.upper()} · {free_text} FREE"))

        add(Path.home(), "Internal")
        mount_roots = [Path("/Volumes")] if sys.platform == "darwin" else [Path("/media"), Path("/mnt")]
        if sys.platform.startswith("linux"):
            user = os.environ.get("USER") or os.environ.get("LOGNAME")
            if user:
                mount_roots.insert(0, Path("/run/media") / user)
                mount_roots.insert(0, Path("/media") / user)
        for mount_root in mount_roots:
            if not mount_root.is_dir():
                continue
            try:
                children = sorted(
                    (path for path in mount_root.iterdir() if not path.name.startswith(".")),
                    key=lambda path: path.name.casefold(),
                )
            except OSError:
                continue
            for child in children:
                add(child, child.name)
        return roots


class CarvGuiWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self._shutdown_started = False
        self._gui_config = self._load_gui_config()
        self._recent_service_ids = self._read_recent_service_ids()
        self._configured_out_default = self._gui_config.get(
            GUI_CONFIG_SECTION, GUI_CONFIG_DEFAULT_OUT_KEY, fallback=""
        ).strip()
        self._source_selected = False
        self._output_selected = False
        self._output_writable = False
        self._filters_visited = False
        self._filter_selection_cache = {"category": {}, "format": {}}
        self._syncing_category_formats = False
        self._syncing_image_only_mode = False
        self._mode_before_image_only = "Raw File Hunt"
        self._manual_start_bytes = None
        self._manual_limit_bytes = None
        self._selected_source = None
        self._selected_output = ""
        self._selected_folders = []
        self._process = None
        self._process_started_with_sudo = False
        self._process_output = []
        self._run_command_parts = []
        self._live_metrics = {}
        self._run_context_facts = {}
        self._event_log_lines = []
        self._event_log_progress_text = ""
        self._run_event_suppressed = {}
        self._run_event_seen_signatures = set()
        self._run_event_signature_labels = {}
        self._run_ntfs_geometry = {}
        self._run_progress_authority = ""
        self._hfs_progress_cache = {}
        self._last_hfs_progress_percent = 0.0
        self._last_run_display_percent = 0.0
        self._evidence_cache = {"stamp": None, "data": None}
        self._tsv_rows_cache = {}
        self._last_evidence_refresh_at = 0.0
        self._hfs_evidence_refresh_pending = False
        self._hfs_legacy_recovery_cache = None
        self._modern_recovery_evidence_cache = None
        self._activity_last_position = -1
        self._activity_last_signature = ""
        self._activity_last_progress_at = 0.0
        self._activity_last_problem_signature = ""
        self._activity_known_error_segments = []
        self._activity_known_skipped_segments = []
        self._activity_latest_output_count = -1
        self._activity_latest_output = ""
        self._last_state_monitor_permission_warning_at = 0.0
        self._process_output_lock = threading.Lock()
        self._process_reader_thread = None
        self._run_started_at = 0.0
        self._run_started_wall_time = 0.0
        self._run_previous_elapsed_seconds = 0
        self._run_elapsed_recorded = False
        self._stop_requested = False
        self._recovery_known_pids = set()
        self._recovery_known_pgids = set()
        self._recovery_lingering_reported = False
        self._recovery_launcher_exit_seen_at = 0.0
        self._kernel_reboot_required = False
        self._run_requested_make_image_first = False
        self._continue_image_requested = False
        self._ddrescue_continue_available = False
        self._ddrescue_image_only_run = False
        self._current_run_dir = None
        self._done_output_target = None
        self._done_summary_text = ""
        self._done_live_last_refresh_at = 0.0
        self._done_live_ledger_path = ""
        self._done_live_ledger_pos = 0
        self._done_live_root_path = ""
        self._done_live_seen_paths = set()
        self._done_live_dir_items = {}
        self._done_live_dir_counts = {}
        self._done_live_dir_bytes = {}
        self._done_live_files = 0
        self._done_live_bytes = 0
        self._done_live_unidentified = 0
        self._done_live_embedded = 0
        self._done_exact_catalog_duplicate_rows = []
        self._done_exact_catalog_duplicate_paths = set()
        self._done_exact_catalog_duplicate_bytes = 0
        self._done_exact_catalog_duplicate_unresolved = 0
        self._done_exact_catalog_duplicate_embedded = 0
        self._done_recovered_root = None
        self._done_lazy_generation = 0
        self._done_lazy_next_token = 1
        self._done_lazy_jobs = {}
        self._done_lazy_results = []
        self._done_lazy_results_lock = threading.Lock()
        self._done_lazy_scan_lock = threading.Lock()
        self._done_lazy_threads = []
        self._done_lazy_page_size = 500
        self._process_family_cache_at = 0.0
        self._process_family_cache = ({}, set(), set())
        self._resource_sample_at = 0.0
        self._develop_time_buckets = {
            "source": 0.0,
            "validation": 0.0,
            "output_wait": 0.0,
            "metadata": 0.0,
            "restart_other": 0.0,
        }
        self._develop_time_last_sample_at = 0.0
        self._source_test_thread = None
        self._source_test_process = None
        self._source_test_started_with_sudo = False
        self._source_test_result = None
        self._source_test_spinner_index = 0
        self._hypersafe_thread = None
        self._hypersafe_process = None
        self._hypersafe_started_with_sudo = False
        self._hypersafe_result = None
        self._hypersafe_spinner_index = 0
        self._hypersafe_run_dir = None
        self._hypersafe_stop_stage = 0
        self._run_busy_index = 0
        self._run_activity_body = ""
        self._run_activity_spinner_index = 0
        self._source_test_timer = QTimer(self)
        self._source_test_timer.setInterval(250)
        self._source_test_timer.timeout.connect(
            guarded_qt_timer(self._poll_source_jpeg_test, "source JPEG test")
        )
        self._hypersafe_timer = QTimer(self)
        self._hypersafe_timer.setInterval(250)
        self._hypersafe_timer.timeout.connect(
            guarded_qt_timer(self._poll_hypersafe_folder_fetch, "Hypersafe folder fetch")
        )
        self._run_busy_timer = QTimer(self)
        self._run_busy_timer.setInterval(180)
        self._run_busy_timer.timeout.connect(
            guarded_qt_timer(self._advance_run_busy_indicator, "run heartbeat")
        )
        self._done_lazy_timer = QTimer(self)
        self._done_lazy_timer.setInterval(120)
        self._done_lazy_timer.timeout.connect(
            guarded_qt_timer(self._poll_done_lazy_results, "lazy Done tree")
        )
        self._process_timer = QTimer(self)
        # QTimer defaults to a zero-millisecond interval.  During a recovery
        # that turns state polling into an event-loop busy spin: the GUI keeps
        # reparsing state and running process-family checks as fast as one CPU
        # can execute them. Two state refreshes per second still feels live;
        # the separate heartbeat timer keeps the activity spinner moving.
        self._process_timer.setInterval(500)
        self._process_timer.timeout.connect(
            guarded_qt_timer(self._poll_recovery_process, "recovery monitor")
        )
        self.setWindowTitle(f"Carv {CARV_VERSION}  /  Recovery workspace ({QT_LIB})")
        self.resize(1500, 900)
        self.setMinimumSize(1200, 760)
        self.setStyleSheet(
            f"""
            QMainWindow {{ background: {BG}; }}
            QWidget {{ color: {TEXT}; font-size: 13px; font-family: "{ui_font_family()}"; }}
            QLabel {{
                color: {TEXT};
            }}
            QLineEdit, QComboBox, QPlainTextEdit, QTextEdit {{
                background: {SUBTLE};
                border: 1px solid {BORDER};
                border-radius: 4px;
                padding: 8px;
                selection-background-color: {ACCENT};
                selection-color: #101609;
            }}
            QLineEdit:disabled, QComboBox:disabled,
            QPlainTextEdit:disabled, QTextEdit:disabled {{
                background: #24292e;
                border-color: #444b52;
                color: #747d85;
            }}
            QScrollArea {{
                background: {TAB_ACTIVE};
                border: 1px solid {BORDER};
                border-radius: 5px;
            }}
            QScrollArea > QWidget > QWidget {{
                background: {TAB_ACTIVE};
            }}
            QScrollArea QWidget {{
                background: {TAB_ACTIVE};
            }}
            QScrollArea:disabled,
            QScrollArea:disabled > QWidget > QWidget,
            QScrollArea:disabled QWidget {{
                background: #24292e;
                border-color: #444b52;
                color: #747d85;
            }}
            QTreeWidget {{
                background: #14191e;
                alternate-background-color: #171d22;
                border: 1px solid {BORDER};
                border-radius: 4px;
                outline: none;
                font-size: 12px;
            }}
            QTreeWidget::item {{
                height: 25px;
                padding: 0 5px;
                border: none;
            }}
            QTreeWidget::item:selected {{
                background: #1d4937;
                color: {TEXT};
                border-left: 2px solid {ACCENT};
            }}
            QTreeWidget::item:hover {{ background: #1b252b; }}
            QTreeWidget::item:selected:hover {{
                background: #24533f;
                color: {TEXT};
                border-left: 2px solid {ACCENT};
            }}
            QHeaderView::section {{
                background: #101519;
                color: {MUTED};
                border: none;
                border-bottom: 1px solid {BORDER};
                padding: 7px 8px;
                font-family: "{mono_font_family()}";
                font-size: 10px;
                font-weight: 700;
                letter-spacing: 0.7px;
            }}
            QCheckBox {{ color: {TEXT}; }}
            QCheckBox::indicator {{
                width: 13px; height: 13px;
                border: 1px solid {STEEL_DARK}; border-radius: 2px;
                background: {SUBTLE};
            }}
            QCheckBox::indicator:checked {{
                background: {ACCENT}; border-color: {ACCENT};
            }}
            QCheckBox:disabled {{ color: #747d85; }}
            QCheckBox::indicator:disabled {{
                background: #2a3035; border-color: #505860;
            }}
            QCheckBox::indicator:checked:disabled {{
                background: #687179; border-color: #7a838b;
            }}
            QRadioButton {{ color: {TEXT}; }}
            QRadioButton::indicator {{
                width: 13px; height: 13px;
                border: 1px solid {STEEL_DARK}; border-radius: 7px;
                background: {SUBTLE};
            }}
            QRadioButton::indicator:checked {{
                background: {ACCENT}; border-color: {ACCENT};
            }}
            QRadioButton:disabled {{ color: #747d85; }}
            QRadioButton::indicator:disabled {{
                background: #2a3035; border-color: #505860;
            }}
            QRadioButton::indicator:checked:disabled {{
                background: #687179; border-color: #7a838b;
            }}
            QLabel:disabled {{ color: #747d85; }}
            QSplitter::handle {{ background: {BG}; width: 7px; }}
            QSplitter::handle:hover {{ background: {ACCENT}; }}
            QTabWidget::pane {{
                border: 1px solid {BORDER};
                background: {TAB_ACTIVE};
                top: 0px;
            }}
            QTabWidget:disabled::pane {{
                border-color: #444b52;
                background: #24292e;
            }}
            QTabWidget::tab-bar {{
                alignment: left;
                left: 0px;
            }}
            QTabBar::tab {{
                background: {TAB_INACTIVE};
                color: {MUTED};
                border: 1px solid {BORDER};
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                font-family: "{mono_font_family()}";
                font-size: 10px;
                font-weight: 700;
                letter-spacing: 0.7px;
                padding: 9px 12px 8px 12px;
                margin-right: 4px;
                min-width: 78px;
            }}
            QTabBar::tab:selected {{
                background: {TAB_ACTIVE};
                color: {TEXT};
                border-color: {BORDER};
                margin-bottom: -1px;
            }}
            QTabBar::tab:!selected {{
                margin-top: 4px;
            }}
            QTabBar::tab:disabled {{
                background: #24292e;
                border-color: #444b52;
                color: #747d85;
            }}
            QSlider::groove:horizontal {{
                border: 1px solid {STEEL_EDGE};
                background: #11161a;
                height: 5px;
                border-radius: 2px;
            }}
            QSlider::sub-page:horizontal {{
                background: {ACCENT};
                border: 1px solid {ACCENT};
                height: 5px;
                border-radius: 2px;
            }}
            QSlider::handle:horizontal {{
                background: #c7f5dd;
                border: 1px solid {ACCENT};
                width: 11px;
                margin: -5px 0;
                border-radius: 2px;
            }}
            QPushButton {{
                background: {SUBTLE};
                border: 1px solid {BORDER};
                color: {TEXT};
                border-radius: 4px;
                padding: 6px 12px;
            }}
            QPushButton:hover {{
                border-color: {ACCENT};
            }}
            QDialogButtonBox QPushButton {{
                min-width: 112px;
                padding: 9px 14px;
                font-weight: 600;
            }}
            QPushButton#dialogPrimary {{
                min-width: 168px;
                color: {ACCENT};
                background: #17231e;
                border: 1px solid #08a960;
                font-weight: 700;
                letter-spacing: 0.4px;
            }}
            QPushButton#dialogPrimary:hover {{
                color: #44e69b;
                background: #1d3328;
                border-color: {ACCENT};
            }}
            QPushButton#dialogPrimary:disabled {{
                background: #17201c;
                border-color: #304038;
                color: #58655f;
            }}
            QPushButton:disabled {{
                background: #171c21;
                border-color: #2b343c;
                color: #58636d;
            }}
            QPushButton#readSourceButton {{
                background: #17231e;
                border: 1px solid #287d58;
                color: {ACCENT};
                font-family: "{mono_font_family()}";
                font-size: 10px;
                font-weight: 700;
                letter-spacing: 0.8px;
                padding: 9px 14px;
            }}
            QPushButton#readSourceButton:disabled {{
                background: #14191e;
                border-color: {BORDER};
                color: #58636d;
            }}
            QPushButton#startRecoveryButton {{
                color: #111609;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 1px;
                padding: 10px 34px 10px 16px;
                border-radius: 4px;
                border: 1px solid #08a960;
                background: #078e51;
                outline: none;
            }}
            QPushButton#startRecoveryButton:hover {{
                border: 1px solid {ACCENT};
                background: #08a960;
            }}
            QPushButton#startRecoveryButton:pressed {{
                padding-top: 9px;
                padding-bottom: 7px;
                background: #057140;
            }}
            """
        )
        self.setCentralWidget(self._build_ui())

    def _load_gui_config(self) -> configparser.ConfigParser:
        parser = configparser.ConfigParser()
        path = app_config_path()
        if not path.exists():
            legacy_path = legacy_app_config_path()
            if legacy_path != path and legacy_path.exists():
                path = legacy_path
        if path.exists():
            try:
                parser.read(path, encoding="utf-8")
            except configparser.Error:
                return configparser.ConfigParser()
        return parser

    def _read_recent_service_ids(self):
        try:
            raw = self._gui_config.get(
                GUI_CONFIG_SECTION, GUI_CONFIG_RECENT_SERVICE_IDS_KEY, fallback=""
            ).strip()
        except configparser.Error:
            return []
        if not raw:
            return []
        try:
            values = json.loads(raw)
        except (TypeError, ValueError):
            values = raw.splitlines()
        result = []
        for value in values if isinstance(values, list) else []:
            text = str(value or "").strip()
            if text and text not in result:
                result.append(text)
            if len(result) == 3:
                break
        return result

    def _write_gui_config(self) -> bool:
        path = app_config_path()
        temporary = path.with_name(path.name + ".tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with temporary.open("w", encoding="utf-8") as handle:
                self._gui_config.write(handle)
            os.replace(temporary, path)
            return True
        except OSError:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            return False

    def closeEvent(self, event) -> None:
        if self._kernel_reboot_required:
            QMessageBox.critical(
                self,
                "Kernel I/O hang · reboot required",
                "Linux has reported a storage-path kernel crash while ddrescue is "
                "blocked in uninterruptible I/O. The image and map are saved, but "
                "the blocked worker cannot be removed safely from this boot.\n\n"
                "Restart the recovery computer before resuming this Service ID.",
            )
            event.ignore()
            return
        live_recovery_family, _ = self._refresh_recovery_process_family(force=True)
        if ((self._process is not None and self._process.poll() is None) or
                live_recovery_family):
            QMessageBox.warning(
                self,
                "Recovery still running",
                "Carv or one of its recovery workers is still active. Stop the recovery "
                "cleanly from the Run tab before closing this window.",
            )
            event.ignore()
            return
        source_test_live = (
            (self._source_test_thread is not None and self._source_test_thread.is_alive()) or
            (self._source_test_process is not None and self._source_test_process.poll() is None)
        )
        if source_test_live:
            if self._source_test_process is not None and self._source_test_process.poll() is None:
                answer = QMessageBox.warning(
                    self,
                    "JPEG test still running",
                    "A source JPEG test is still active. Kill the test process before closing?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes,
                )
                if answer == QMessageBox.StandardButton.Yes:
                    self._signal_source_test_process(signal.SIGKILL, "Kill JPEG test")
            else:
                QMessageBox.warning(
                    self,
                    "JPEG test still running",
                    "A source JPEG test is starting or finishing. Wait a moment and close again.",
                )
            event.ignore()
            return
        hypersafe_live = (
            (self._hypersafe_thread is not None and self._hypersafe_thread.is_alive()) or
            (self._hypersafe_process is not None and self._hypersafe_process.poll() is None)
        )
        if hypersafe_live:
            if self._hypersafe_process is not None and self._hypersafe_process.poll() is None:
                answer = QMessageBox.warning(
                    self,
                    "Hypersafe fetch still running",
                    "The ddrescue metadata fetch is still active. Kill it before closing? "
                    "Its image and map will remain resumable.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if answer == QMessageBox.StandardButton.Yes:
                    if self._signal_hypersafe_process(
                            signal.SIGKILL, "Kill Hypersafe fetch"):
                        self._hypersafe_stop_stage = 2
            else:
                QMessageBox.warning(
                    self,
                    "Hypersafe fetch still running",
                    "The metadata fetch is starting or finishing. Wait a moment and close again.",
                )
            event.ignore()
            return
        self._shutdown_gui_workers()
        super().closeEvent(event)

    def _shutdown_gui_workers(self) -> None:
        """Quiesce non-recovery background work before Python tears Qt down."""
        if self._shutdown_started:
            return
        self._shutdown_started = True

        for timer_name in (
            "_source_test_timer",
            "_hypersafe_timer",
            "_run_busy_timer",
            "_done_lazy_timer",
            "_process_timer",
        ):
            timer = getattr(self, timer_name, None)
            if timer is not None:
                timer.stop()

        source_panel = getattr(self, "source_panel", None)
        if source_panel is not None:
            source_panel.shutdown()

        self._hfs_evidence_refresh_pending = False
        self._done_lazy_generation += 1
        self._done_lazy_jobs.clear()
        with self._done_lazy_results_lock:
            self._done_lazy_results.clear()

        deadline = time.monotonic() + 0.4
        threads = list(getattr(self, "_done_lazy_threads", ()))
        if self._process_reader_thread is not None:
            threads.append(self._process_reader_thread)
        for thread in threads:
            if thread is None or not thread.is_alive():
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            thread.join(timeout=remaining)

    def _remember_setup_preferences(self) -> None:
        if not self._gui_config.has_section(GUI_CONFIG_SECTION):
            self._gui_config.add_section(GUI_CONFIG_SECTION)
        service_id = self.service_id_combo.currentText().strip()
        recent = [service_id] if service_id else []
        recent.extend(value for value in self._recent_service_ids if value != service_id)
        self._recent_service_ids = recent[:3]
        self._gui_config.set(
            GUI_CONFIG_SECTION,
            GUI_CONFIG_RECENT_SERVICE_IDS_KEY,
            json.dumps(self._recent_service_ids, ensure_ascii=False),
        )
        if getattr(self, "output_panel", None) is not None and self.output_panel.remember_output.isChecked():
            current_default = self._gui_config.get(
                GUI_CONFIG_SECTION, GUI_CONFIG_DEFAULT_OUT_KEY, fallback=""
            ).strip()
            if self._selected_output and self._selected_output != current_default:
                answer = QMessageBox.question(
                    self,
                    "Remember output folder",
                    f"Use this as the preferred output folder for future jobs?\n\n{self._selected_output}",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes,
                )
                if answer == QMessageBox.StandardButton.Yes:
                    self._gui_config.set(GUI_CONFIG_SECTION, GUI_CONFIG_DEFAULT_OUT_KEY, self._selected_output)
        self._write_gui_config()

    def _build_ui(self) -> QWidget:
        tabs = QTabWidget()
        self.main_tabs = tabs
        tabs.setObjectName("mainTabs")
        tabs.setDocumentMode(False)
        tabs.tabBar().setExpanding(False)
        tabs.addTab(self._build_setup_workspace(), "SETUP")
        tabs.addTab(self._build_run_workspace(), "RUN")
        tabs.addTab(self._build_done_workspace(), "DONE")
        return tabs

    def _build_setup_workspace(self) -> QWidget:
        root = QWidget()
        root.setStyleSheet(
            """
            QWidget {
                background: transparent;
            }
            """
        )
        outer = QVBoxLayout(root)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(10)

        header = QHBoxLayout()
        header.setContentsMargins(2, 0, 2, 0)
        header.setSpacing(12)

        title_block = QVBoxLayout()
        title_block.setContentsMargins(0, 0, 0, 0)
        title_block.setSpacing(3)
        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(10)
        title = QLabel("CARV")
        title.setStyleSheet(
            f"font-size: 26px; font-weight: 800; letter-spacing: 3px; color: {TEXT}; background: transparent;"
        )
        title_row.addWidget(title)
        logo_label = QLabel()
        logo_label.setStyleSheet("background: transparent; border: none;")
        logo_pixmap = QPixmap(CARV_TITLE_LOGO_PATH)
        if not logo_pixmap.isNull():
            logo_label.setPixmap(
                logo_pixmap.scaledToHeight(
                    28,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )
            logo_label.setFixedHeight(30)
            logo_label.setToolTip("Namnby")
            title_row.addWidget(logo_label)
        title_row.addStretch(1)
        subtitle = QLabel("FORENSIC RECOVERY WORKSTATION")
        subtitle.setStyleSheet(
            f"color: {MUTED}; background: transparent; font-family: '{mono_font_family()}'; "
            "font-size: 10px; font-weight: 700; letter-spacing: 1.3px;"
        )
        title_block.addLayout(title_row)
        title_block.addWidget(subtitle)
        header.addLayout(title_block)
        header.addStretch(1)

        self.eta_badge = QLabel("READ ETA\nCHOOSE SOURCE")
        self.eta_badge.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.eta_badge.setStyleSheet(
            f"color: {ACCENT}; background: {PANEL}; border: 1px solid {BORDER}; border-radius: 4px; "
            f"padding: 7px 10px; font-family: '{mono_font_family()}'; font-size: 10px; "
            "font-weight: 700; letter-spacing: 0.8px;"
        )
        header.addWidget(self.eta_badge)
        outer.addLayout(header)

        workflow = QFrame()
        workflow.setObjectName("workflowStatus")
        workflow.setStyleSheet(
            f"QFrame#workflowStatus {{ background: #14191e; border: 1px solid {BORDER}; border-radius: 4px; }}"
        )
        workflow_layout = QHBoxLayout(workflow)
        workflow_layout.setContentsMargins(10, 8, 10, 8)
        workflow_layout.setSpacing(6)
        self.workflow_marks = {}
        for key, title_text in (("service", "SERVICE ID"), ("source", "SOURCE"), ("output", "OUTPUT")):
            title_label = QLabel(title_text)
            title_label.setStyleSheet(
                f"color: {MUTED}; background: transparent; font-family: '{mono_font_family()}'; "
                "font-size: 10px; font-weight: 700; letter-spacing: 0.8px;"
            )
            mark_label = QLabel("—")
            mark_label.setStyleSheet(
                f"color: {MUTED}; background: transparent; font-family: '{mono_font_family()}'; "
                "font-size: 11px; font-weight: 700;"
            )
            workflow_layout.addWidget(title_label)
            workflow_layout.addWidget(mark_label)
            workflow_layout.addSpacing(14)
            self.workflow_marks[key] = mark_label
        workflow_layout.addStretch(1)
        outer.addWidget(workflow)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setObjectName("setupSplitter")
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(7)
        splitter.setOpaqueResize(True)
        self.setup_plan_panel = self._build_setup_column()
        # The plan panel contains three labelled tabs and the execution rail;
        # below this it starts clipping controls rather than becoming useful.
        self.setup_plan_panel.setMinimumWidth(340)
        self.setup_plan_panel.setMaximumWidth(500)
        splitter.addWidget(self.setup_plan_panel)

        right_stack = QWidget()
        right_layout = QVBoxLayout(right_stack)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)

        source_output_splitter = QSplitter(Qt.Orientation.Horizontal)
        source_output_splitter.setObjectName("sourceOutputSplitter")
        source_output_splitter.setChildrenCollapsible(False)
        source_output_splitter.setHandleWidth(7)
        source_output_splitter.setOpaqueResize(True)
        self.source_panel = SourceTreePanel(
            self._on_selected_source_changed,
            self._on_folder_selection_changed,
            self._run_source_jpeg_test,
        )
        if hasattr(self, "mode_combo"):
            self.source_panel.set_mode(self.mode_combo.currentText())
            self.mode_combo.currentTextChanged.connect(self.source_panel.set_mode)
        self.source_panel.setMinimumWidth(360)
        source_output_splitter.addWidget(self.source_panel)
        self.output_panel = OutputTreePanel(
            self._on_selected_output_changed,
            configured_default=self._configured_out_default,
        )
        self.output_panel.setMinimumWidth(360)
        self.output_panel.set_service_id(self.service_id_combo.currentText())
        self.service_id_combo.currentTextChanged.connect(self.output_panel.set_service_id)
        source_output_splitter.addWidget(self.output_panel)
        source_output_splitter.setStretchFactor(0, 1)
        source_output_splitter.setStretchFactor(1, 1)
        source_output_splitter.setSizes([560, 560])
        self.source_output_splitter = source_output_splitter
        right_layout.addWidget(source_output_splitter, 1)

        self.hypersafe_layout_panel = self._build_hypersafe_layout_panel()
        self.hypersafe_layout_panel.setVisible(False)
        right_layout.addWidget(self.hypersafe_layout_panel)

        splitter.addWidget(right_stack)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([360, 1120])
        self.setup_splitter = splitter

        outer.addWidget(splitter, 1)
        return root

    def _build_hypersafe_layout_panel(self) -> QWidget:
        panel = group_box("HYPERSAFE")
        panel.setMinimumHeight(230)
        panel.setMaximumHeight(275)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 16, 12, 12)
        layout.setSpacing(10)

        heading = QHBoxLayout()
        heading.setSpacing(12)
        strategy_heading = QLabel("RECOVERY STRATEGY")
        strategy_heading.setStyleSheet(
            f"color: {MUTED}; background: transparent; font-family: '{mono_font_family()}'; "
            "font-size: 9px; font-weight: 800; letter-spacing: 0.8px;"
        )
        heading.addWidget(strategy_heading)
        heading.addStretch(1)
        draft_note = QLabel("CONFIGURATION DRAFT")
        draft_note.setStyleSheet(
            f"color: {WARNING}; background: transparent; font-family: '{mono_font_family()}'; "
            "font-size: 9px; font-weight: 800; letter-spacing: 0.8px;"
        )
        heading.addWidget(draft_note)
        layout.addLayout(heading)

        body = QHBoxLayout()
        body.setSpacing(18)

        strategies = QWidget()
        strategies_layout = QVBoxLayout(strategies)
        strategies_layout.setContentsMargins(0, 0, 0, 0)
        strategies_layout.setSpacing(8)
        self.hypersafe_image_now_radio = QRadioButton(
            "1. Image immediately"
        )
        self.hypersafe_priority_radio = QRadioButton(
            "2. Prioritize named folders"
        )
        self.hypersafe_tree_radio = QRadioButton(
            "3. Tree recovery"
        )
        self.hypersafe_image_now_radio.setChecked(True)
        for radio in (
            self.hypersafe_image_now_radio,
            self.hypersafe_priority_radio,
            self.hypersafe_tree_radio,
        ):
            strategies_layout.addWidget(radio)
        strategies_layout.addStretch(1)
        body.addWidget(strategies, 0)

        detail_panel = QFrame()
        detail_panel.setObjectName("hypersafeDetailPanel")
        detail_panel.setMinimumWidth(420)
        detail_panel.setMaximumWidth(650)
        detail_panel.setStyleSheet(
            f"QFrame#hypersafeDetailPanel {{ background: #0d1114; "
            f"border: 1px solid {BORDER}; border-radius: 4px; }}"
        )
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.setContentsMargins(12, 10, 12, 10)
        detail_layout.setSpacing(7)
        self.hypersafe_strategy_title = QLabel()
        self.hypersafe_strategy_title.setStyleSheet(
            f"color: {TEXT}; background: transparent; border: none; "
            f"font-family: '{mono_font_family()}'; font-size: 11px; font-weight: 800;"
        )
        self.hypersafe_strategy_detail = QLabel()
        self.hypersafe_strategy_detail.setWordWrap(True)
        self.hypersafe_strategy_detail.setStyleSheet(
            f"color: {MUTED}; background: transparent; font-family: '{mono_font_family()}'; "
            "font-size: 10px; border: none;"
        )
        self.hypersafe_priority_edit = QPlainTextEdit()
        self.hypersafe_priority_edit.setPlaceholderText(
            "Any remembered part of a folder name, one per line\n"
            "Examples: pics\nCustomer files\n?Project 2024?"
        )
        self.hypersafe_priority_edit.setMaximumHeight(92)
        self.hypersafe_priority_edit.setToolTip(
            "A folder matches when its name contains any entered line, even in "
            "the middle. Uppercase and lowercase are treated alike. Wildcards "
            "are implicit; pics, ?pics? and *pics* mean the same thing."
        )
        self.hypersafe_priority_edit.textChanged.connect(
            self._on_hypersafe_priority_terms_changed
        )
        detail_layout.addWidget(self.hypersafe_strategy_title)
        detail_layout.addWidget(self.hypersafe_strategy_detail)
        detail_layout.addWidget(self.hypersafe_priority_edit, 1)
        self.hypersafe_tree_preview_hint = QLabel(
            'PRESS "PREVIEW FILESYSTEM STRUCTURE" ABOVE'
        )
        self.hypersafe_tree_preview_hint.setWordWrap(True)
        self.hypersafe_tree_preview_hint.setStyleSheet(
            f"color: {ACCENT}; background: transparent; border: none; "
            f"font-family: '{mono_font_family()}'; font-size: 10px; "
            "font-weight: 800; letter-spacing: 0.7px;"
        )
        detail_layout.addWidget(self.hypersafe_tree_preview_hint)
        if hasattr(self, "hypersafe_folder_fetch_button"):
            detail_layout.addWidget(self.hypersafe_folder_fetch_button)
            self.hypersafe_folder_fetch_button.setVisible(False)
        detail_layout.addStretch(1)
        body.addWidget(detail_panel, 0)
        body.addStretch(1)
        layout.addLayout(body, 1)

        for radio in (
            self.hypersafe_image_now_radio,
            self.hypersafe_priority_radio,
            self.hypersafe_tree_radio,
        ):
            radio.toggled.connect(self._refresh_hypersafe_strategy_ui)
        self._refresh_hypersafe_strategy_ui()
        return panel

    def _build_future_tab(self, title_text: str, detail: str) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.addStretch(1)
        title = QLabel(title_text)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            f"color: {TEXT}; font-family: '{mono_font_family()}'; font-size: 22px; "
            "font-weight: 700; letter-spacing: 2px;"
        )
        note = QLabel(detail)
        note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        note.setStyleSheet(f"color: {MUTED}; font-size: 13px;")
        layout.addWidget(title)
        layout.addWidget(note)
        layout.addStretch(1)
        return tab

    def _build_run_workspace(self) -> QWidget:
        root = QWidget()
        outer = QVBoxLayout(root)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.setSpacing(10)

        header = QFrame()
        header.setStyleSheet(
            f"QFrame {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 6px; }}"
        )
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(18, 14, 18, 14)
        header_layout.setSpacing(22)

        identity = QVBoxLayout()
        identity.setSpacing(3)
        identity.addWidget(self._run_caption("ACTIVE SERVICE"))
        self.run_service_value = QLabel("—")
        self.run_service_value.setStyleSheet(
            f"color: {TEXT}; font-family: '{mono_font_family()}'; font-size: 22px; "
            "font-weight: 800; letter-spacing: 1.2px; border: none;"
        )
        identity.addWidget(self.run_service_value)
        self.run_state_value = QLabel("●  IDLE")
        self.run_state_value.setStyleSheet(
            f"color: {MUTED}; font-family: '{mono_font_family()}'; font-size: 10px; "
            "font-weight: 800; letter-spacing: 1px; border: none;"
        )
        identity.addWidget(self.run_state_value)
        header_layout.addLayout(identity, 2)

        percent_block = QVBoxLayout()
        percent_block.setSpacing(0)
        percent_block.addWidget(self._run_caption("OVERALL PROGRESS"), 0, Qt.AlignmentFlag.AlignHCenter)
        self.run_percent_value = QLabel("—")
        self.run_percent_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.run_percent_value.setStyleSheet(
            f"color: {ACCENT}; font-family: '{mono_font_family()}'; font-size: 54px; "
            "font-weight: 800; letter-spacing: -2px; border: none;"
        )
        percent_block.addWidget(self.run_percent_value)
        self.run_post_scan_notice = QLabel("REVISITING ERROR ZONES")
        self.run_post_scan_notice.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.run_post_scan_notice.setVisible(False)
        self.run_post_scan_notice.setStyleSheet(
            f"color: {ACCENT}; font-family: '{mono_font_family()}'; font-size: 11px; "
            "font-weight: 900; letter-spacing: 1.4px; border: none;"
        )
        percent_block.addWidget(self.run_post_scan_notice)
        header_layout.addLayout(percent_block, 3)

        eta = QVBoxLayout()
        eta.setSpacing(3)
        eta.addWidget(self._run_caption("ESTIMATED REMAINING"))
        self.run_eta_value = QLabel("—")
        self.run_eta_value.setStyleSheet(
            f"color: {TEXT}; font-family: '{mono_font_family()}'; font-size: 24px; "
            "font-weight: 700; border: none;"
        )
        eta.addWidget(self.run_eta_value)
        self.run_elapsed_value = QLabel("Elapsed —")
        self.run_elapsed_value.setStyleSheet(f"color: {MUTED}; font-size: 11px; border: none;")
        eta.addWidget(self.run_elapsed_value)
        header_layout.addLayout(eta, 2)

        health = QGridLayout()
        health.setHorizontalSpacing(18)
        health.setVerticalSpacing(2)
        for column, title in enumerate(("CPU", "RAM")):
            health.addWidget(self._run_caption(title), 0, column)
            metric = QLabel("—")
            metric.setStyleSheet(
                f"color: {TEXT}; font-family: '{mono_font_family()}'; font-size: 14px; "
                "font-weight: 700; border: none;"
            )
            health.addWidget(metric, 1, column)
            if title == "CPU":
                self.run_cpu_value = metric
                self.run_cpu_value.setTextFormat(Qt.TextFormat.RichText)
            else:
                self.run_ram_value = metric
        header_layout.addLayout(health, 2)
        outer.addWidget(header)

        evidence = group_box("FILE FINDINGS")
        evidence_layout = QVBoxLayout(evidence)
        evidence_layout.setContentsMargins(12, 16, 12, 10)
        evidence_layout.setSpacing(8)

        progress_row = QHBoxLayout()
        progress_row.setSpacing(10)
        self.run_preview_progress = QProgressBar()
        self.run_preview_progress.setRange(0, 1000)
        self.run_preview_progress.setValue(0)
        self.run_preview_progress.setTextVisible(False)
        self.run_preview_progress.setFixedHeight(12)
        self.run_preview_progress.setStyleSheet(
            f"QProgressBar {{ background: #10151a; border: 1px solid {BORDER}; border-radius: 2px; }}"
            f"QProgressBar::chunk {{ background: {ACCENT}; border-radius: 1px; }}"
        )
        progress_row.addWidget(self.run_preview_progress, 1)
        self.run_cursor_value = QLabel("0 B / —")
        self.run_cursor_value.setStyleSheet(
            f"color: {MUTED}; font-family: '{mono_font_family()}'; font-size: 10px;"
        )
        progress_row.addWidget(self.run_cursor_value)
        evidence_layout.addLayout(progress_row)

        self.run_evidence_map = CumulativeEvidenceWidget()
        evidence_layout.addWidget(self.run_evidence_map)

        key = QHBoxLayout()
        key.setSpacing(16)
        for label, color in (
            ("Read", "#6f9abf"),
            ("Recovered", "#9cff00"),
            ("Dense recover", ACCENT),
            ("Read error", "#ff315c"),
            ("Skipped range", "#e6a23c"),
        ):
            swatch = QFrame()
            swatch.setFixedSize(10, 10)
            swatch.setStyleSheet(f"background: {color}; border: 1px solid #52606b;")
            key.addWidget(swatch)
            key_label = QLabel(label)
            key_label.setStyleSheet(f"color: {MUTED}; font-size: 10px;")
            key.addWidget(key_label)
        key.addStretch(1)
        self.run_evidence_summary = QLabel("No file findings yet")
        self.run_evidence_summary.setStyleSheet(
            f"color: {TEXT}; font-family: '{mono_font_family()}'; font-size: 11px; font-weight: 700;"
        )
        key.addWidget(self.run_evidence_summary)
        evidence_layout.addLayout(key)

        metrics = QGridLayout()
        metrics.setHorizontalSpacing(22)
        self.run_metric_values = {}
        for column, (title, accent) in enumerate((
            ("PHASE", False),
            ("READ SPEED", True),
            ("STALLED", False),
            ("TOTAL FILES", False),
            ("RECOVERED", False),
        )):
            metrics.addWidget(self._run_caption(title), 0, column)
            metric = QLabel("—")
            metric.setWordWrap(True)
            metric.setStyleSheet(
                f"color: {ACCENT if accent else TEXT}; font-family: '{mono_font_family()}'; "
                "font-size: 12px; font-weight: 700;"
            )
            if title == "PHASE":
                metric.setMinimumHeight(34)
                metric.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
            metrics.addWidget(metric, 1, column)
            self.run_metric_values[title] = metric
        evidence_layout.addLayout(metrics)
        self.run_develop_time_row = QLabel(
            "DEVELOP TIME · waiting for samples"
        )
        self.run_develop_time_row.setWordWrap(True)
        self.run_develop_time_row.setToolTip(
            "Sampled wall time in this GUI session. Output wait is detected from "
            "queue/backpressure state; this is a develop aid, not recovery progress."
        )
        self.run_develop_time_row.setStyleSheet(
            f"color: #d0a05a; font-family: '{mono_font_family()}'; "
            "font-size: 10px; font-weight: 700;"
        )
        evidence_layout.addWidget(self.run_develop_time_row)
        outer.addWidget(evidence)

        lower = QSplitter(Qt.Orientation.Horizontal)
        lower.setChildrenCollapsible(False)

        activity = group_box("ACTIVITY")
        activity_layout = QVBoxLayout(activity)
        activity_layout.setContentsMargins(10, 16, 10, 10)
        self.run_activity_text = QPlainTextEdit()
        self.run_activity_text.setReadOnly(True)
        self.run_activity_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self._set_run_activity_body("")
        self.run_activity_text.setStyleSheet(
            f"font-family: '{mono_font_family()}'; font-size: 11px; padding: 12px;"
        )
        activity_layout.addWidget(self.run_activity_text)
        lower.addWidget(activity)

        right = QSplitter(Qt.Orientation.Vertical)
        right.setChildrenCollapsible(False)
        context = group_box("RUN CONTEXT")
        context_layout = QGridLayout(context)
        context_layout.setContentsMargins(10, 16, 10, 10)
        context_layout.setHorizontalSpacing(12)
        context_layout.setVerticalSpacing(5)
        self.run_context_values = {}
        for row, label in enumerate(self._run_context_field_names()):
            left = self._run_caption(label.upper())
            right_value = QLabel()
            right_value.setWordWrap(True)
            right_value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            right_value.setStyleSheet(
                f"color: {TEXT}; font-family: '{mono_font_family()}'; font-size: 10px;"
            )
            context_layout.addWidget(left, row, 0)
            context_layout.addWidget(right_value, row, 1)
            self.run_context_values[label] = right_value
        self._render_run_context()
        context_layout.setColumnStretch(1, 1)
        right.addWidget(context)

        event_log = group_box("EVENT LOG")
        event_layout = QVBoxLayout(event_log)
        event_layout.setContentsMargins(10, 16, 10, 10)
        stream_label = QLabel("OPERATOR EVENTS  /  IMPORTANT STATE CHANGES + PROBLEMS")
        stream_label.setStyleSheet(
            f"color: {MUTED}; font-family: '{mono_font_family()}'; font-size: 9px; "
            "font-weight: 700; letter-spacing: 0.8px;"
        )
        event_layout.addWidget(stream_label)
        self.run_event_log = QPlainTextEdit()
        self.run_event_log.setReadOnly(True)
        self.run_event_log.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.run_event_log.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        self.run_event_log.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.run_event_log.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._reset_event_log(waiting=True)
        self.run_event_log.setStyleSheet(
            f"QPlainTextEdit {{ background: #090c0e; color: #b9c5cc; "
            f"border: 1px solid #2b343c; border-radius: 2px; padding: 9px; "
            f"font-family: '{mono_font_family()}'; font-size: 10px; selection-background-color: #285440; }}"
            "QScrollBar:vertical, QScrollBar:horizontal { background: #0d1114; }"
        )
        event_layout.addWidget(self.run_event_log)
        right.addWidget(event_log)
        right.setSizes([190, 230])
        lower.addWidget(right)
        lower.setSizes([700, 700])
        outer.addWidget(lower, 1)

        footer = QHBoxLayout()
        self.run_monitor_status = QLabel("MONITOR IDLE")
        self.run_monitor_status.setStyleSheet(
            f"color: {MUTED}; font-family: '{mono_font_family()}'; font-size: 9px; "
            "font-weight: 700; letter-spacing: 0.8px;"
        )
        footer.addWidget(self.run_monitor_status)
        footer.addStretch(1)
        self.continue_image_button = QPushButton("STOP IMAGING · RECOVER FROM IMAGE")
        self.continue_image_button.setVisible(False)
        self.continue_image_button.setEnabled(False)
        self.continue_image_button.setToolTip(
            "Stop ddrescue cleanly, skip the remaining source retries in this run, "
            "and recover files from the partial image already written."
        )
        self.continue_image_button.clicked.connect(self._request_continue_from_source_image)
        footer.addWidget(self.continue_image_button)
        self.stop_button = QPushButton("STOP RECOVERY")
        self.stop_button.setEnabled(False)
        self.stop_button.setToolTip(
            "First click requests a clean stop. If the process remains blocked, click again to kill it."
        )
        self.stop_button.clicked.connect(self._stop_recovery)
        self.stop_button.setStyleSheet(
            "QPushButton { color: #e6b6b6; border-color: #754747; background: #271b1d; "
            "font-weight: 700; letter-spacing: 0.8px; padding: 8px 16px; }"
            "QPushButton:hover { border-color: #b95c5c; background: #352124; }"
        )
        footer.addWidget(self.stop_button)
        outer.addLayout(footer)
        return root

    def _run_caption(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setStyleSheet(
            f"color: {MUTED}; font-family: '{mono_font_family()}'; font-size: 9px; "
            "font-weight: 800; letter-spacing: 1px; border: none;"
        )
        return label

    def _build_done_workspace(self) -> QWidget:
        root = QWidget()
        outer = QVBoxLayout(root)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.setSpacing(10)

        banner = QFrame()
        banner.setStyleSheet(
            "QFrame { background: #14251d; border: 1px solid #168a55; border-radius: 6px; }"
        )
        banner_layout = QHBoxLayout(banner)
        banner_layout.setContentsMargins(22, 15, 22, 15)
        banner_layout.setSpacing(24)

        status_block = QVBoxLayout()
        status_block.setSpacing(1)
        self.done_status_label = QLabel("READY")
        self.done_status_label.setStyleSheet(
            f"color: {ACCENT}; font-family: '{mono_font_family()}'; font-size: 48px; "
            "font-weight: 900; letter-spacing: 3px; border: none;"
        )
        status_block.addWidget(self.done_status_label)
        self.done_status_detail = QLabel("NO FINISHED RUN")
        self.done_status_detail.setStyleSheet(
            f"color: #b8e7cf; font-family: '{mono_font_family()}'; font-size: 10px; "
            "font-weight: 800; letter-spacing: 1.2px; border: none;"
        )
        status_block.addWidget(self.done_status_detail)
        banner_layout.addLayout(status_block, 2)

        completion = QVBoxLayout()
        completion.setSpacing(3)
        completion.addWidget(self._run_caption("SERVICE ID"))
        self.done_service_value = QLabel("—")
        self.done_service_value.setStyleSheet(
            f"color: {TEXT}; font-family: '{mono_font_family()}'; font-size: 21px; "
            "font-weight: 800; border: none;"
        )
        completion.addWidget(self.done_service_value)
        self.done_finished_value = QLabel("No finished run")
        self.done_finished_value.setStyleSheet(f"color: {MUTED}; font-size: 11px; border: none;")
        completion.addWidget(self.done_finished_value)
        banner_layout.addLayout(completion, 2)

        duration = QVBoxLayout()
        duration.setSpacing(3)
        duration.addWidget(self._run_caption("ACTUAL RUNTIME"))
        self.done_runtime_value = QLabel("—")
        self.done_runtime_value.setStyleSheet(
            f"color: {TEXT}; font-family: '{mono_font_family()}'; font-size: 24px; "
            "font-weight: 700; border: none;"
        )
        duration.addWidget(self.done_runtime_value)
        self.done_runtime_note = QLabel("Measured by this GUI session")
        self.done_runtime_note.setStyleSheet(f"color: {MUTED}; font-size: 11px; border: none;")
        duration.addWidget(self.done_runtime_note)
        banner_layout.addLayout(duration, 2)
        outer.addWidget(banner)

        stats = QHBoxLayout()
        stats.setSpacing(8)
        self.done_stat_values = {}
        self.done_stat_notes = {}
        for title, value, note, color in (
            ("RECOVERED", "—", "Awaiting completed run", ACCENT),
            ("NAMED", "—", "Awaiting completed run", TEXT),
            ("UNIDENTIFIED", "—", "Awaiting completed run", "#d5a84b"),
            ("TROUBLE", "—", "Awaiting file findings", "#e06b75"),
        ):
            card = QFrame()
            card.setStyleSheet(
                f"QFrame {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 5px; }}"
            )
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(13, 10, 13, 10)
            card_layout.setSpacing(2)
            card_layout.addWidget(self._run_caption(title))
            value_label = QLabel(value)
            value_label.setStyleSheet(
                f"color: {color}; font-family: '{mono_font_family()}'; font-size: 25px; "
                "font-weight: 800; border: none;"
            )
            card_layout.addWidget(value_label)
            self.done_stat_values[title] = value_label
            note_label = QLabel(note)
            note_label.setStyleSheet(f"color: {MUTED}; font-size: 10px; border: none;")
            card_layout.addWidget(note_label)
            self.done_stat_notes[title] = note_label
            stats.addWidget(card, 1)
        outer.addLayout(stats)

        details = QSplitter(Qt.Orientation.Horizontal)
        details.setChildrenCollapsible(False)

        recovered_box = group_box("RECOVERED FOLDERS / FILES")
        recovered_layout = QVBoxLayout(recovered_box)
        recovered_layout.setContentsMargins(10, 16, 10, 10)
        recovered_layout.setSpacing(7)
        tree_note = QLabel(
            "Output tree · collapse and reopen a folder to refresh it · "
            "double-click a recovered file to open it"
        )
        tree_note.setStyleSheet(f"color: {MUTED}; font-size: 10px;")
        recovered_layout.addWidget(tree_note)

        self.done_recovered_tree = QTreeWidget()
        self.done_recovered_tree.setColumnCount(3)
        self.done_recovered_tree.setHeaderLabels(["NAME", "CONTENTS", "SIZE"])
        self.done_recovered_tree.setAlternatingRowColors(True)
        self.done_recovered_tree.setRootIsDecorated(True)
        self.done_recovered_tree.setUniformRowHeights(True)
        self.done_recovered_tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.done_recovered_tree.itemExpanded.connect(self._expand_done_recovered_item)
        self.done_recovered_tree.itemCollapsed.connect(self._invalidate_done_recovered_item)
        self.done_recovered_tree.itemDoubleClicked.connect(self._open_done_recovered_item)
        self.done_recovered_tree.addTopLevelItem(
            QTreeWidgetItem(["No finished run", "0 files", "0 B"])
        )
        self.done_recovered_tree.setColumnWidth(0, 310)
        self.done_recovered_tree.setColumnWidth(1, 125)
        recovered_layout.addWidget(self.done_recovered_tree, 1)

        path_row = QHBoxLayout()
        self.done_output_path_label = QLabel("—")
        self.done_output_path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.done_output_path_label.setStyleSheet(
            f"color: {MUTED}; font-family: '{mono_font_family()}'; font-size: 10px;"
        )
        path_row.addWidget(self.done_output_path_label, 1)
        self.done_open_output_button = QPushButton("OPEN OUTPUT FOLDER")
        self.done_open_output_button.setEnabled(False)
        self.done_open_output_button.clicked.connect(self._open_done_output_folder)
        path_row.addWidget(self.done_open_output_button)
        recovered_layout.addLayout(path_row)
        details.addWidget(recovered_box)

        summary_box = group_box("RUN SUMMARY")
        summary_layout = QVBoxLayout(summary_box)
        summary_layout.setContentsMargins(12, 16, 12, 10)
        summary_layout.setSpacing(8)

        summary_grid = QGridLayout()
        summary_grid.setHorizontalSpacing(16)
        summary_grid.setVerticalSpacing(7)
        self.done_summary_values = {}
        summary_rows = ("Source", "Destination", "Mode", "Filesystem", "Scope", "Filters", "Read", "Evidence", "Trouble")
        for row, title in enumerate(summary_rows):
            summary_grid.addWidget(self._run_caption(title.upper()), row, 0)
            value_label = QLabel("—")
            value_label.setWordWrap(True)
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value_label.setStyleSheet(
                f"color: {TEXT}; font-family: '{mono_font_family()}'; font-size: 10px;"
            )
            summary_grid.addWidget(value_label, row, 1)
            self.done_summary_values[title] = value_label
        summary_grid.setColumnStretch(1, 1)
        summary_layout.addLayout(summary_grid)

        result_note = QFrame()
        result_note.setStyleSheet(
            f"QFrame {{ background: #12171b; border: 1px solid {BORDER}; border-radius: 3px; }}"
        )
        result_layout = QVBoxLayout(result_note)
        result_layout.setContentsMargins(10, 9, 10, 9)
        result_layout.setSpacing(4)
        result_layout.addWidget(self._run_caption("OPERATOR NOTE"))
        self.done_operator_note = QLabel("No completed run.")
        self.done_operator_note.setWordWrap(True)
        self.done_operator_note.setStyleSheet(f"color: {TEXT}; font-size: 11px; border: none;")
        result_layout.addWidget(self.done_operator_note)
        summary_layout.addWidget(result_note)
        summary_layout.addStretch(1)

        report_row = QHBoxLayout()
        report_row.addStretch(1)
        self.done_report_button = QPushButton("COPY RUN SUMMARY")
        self.done_report_button.setEnabled(False)
        self.done_report_button.clicked.connect(self._copy_done_summary)
        report_row.addWidget(self.done_report_button)
        summary_layout.addLayout(report_row)
        details.addWidget(summary_box)

        details.setSizes([760, 640])
        outer.addWidget(details, 1)
        return root

    def _build_setup_column(self) -> QWidget:
        panel = QFrame()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        plan_box = group_box("01  /  RECOVERY")
        plan_layout = QVBoxLayout(plan_box)
        plan_layout.setContentsMargins(12, 16, 12, 12)
        plan_layout.setSpacing(8)

        self.plan_tabs = QTabWidget()
        self.plan_tab_bar = HighlightTabBar()
        self.plan_tabs.setTabBar(self.plan_tab_bar)
        self.plan_tabs.setDocumentMode(False)
        self.plan_tabs.tabBar().setExpanding(False)
        self.plan_tabs.tabBar().setDrawBase(False)
        self.plan_tabs.addTab(self._build_plan_tab(), "PLAN")
        self.plan_tabs.addTab(self._build_filter_tab(), "FILTERS")
        self.plan_tabs.addTab(self._build_advanced_tab(), "ADVANCED")
        self.plan_tabs.currentChanged.connect(self._on_plan_tab_changed)
        self._update_plan_mode_ui(self.mode_combo.currentText())
        plan_layout.addWidget(self.plan_tabs)
        layout.addWidget(plan_box, 1)

        command_box = group_box("COMMAND PREVIEW")
        command_layout = QVBoxLayout(command_box)
        command_layout.setContentsMargins(12, 16, 12, 12)
        command_layout.setSpacing(10)

        self.command_preview = QPlainTextEdit()
        self.command_preview.setReadOnly(True)
        self.command_preview.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.command_preview.setWordWrapMode(QTextOption.WrapMode.WordWrap)
        self.command_preview.setStyleSheet(
            f"background: #101519; color: {ACCENT}; border: 1px solid {BORDER}; "
            f"border-radius: 4px; padding: 10px; font-family: '{mono_font_family()}'; font-size: 11px;"
        )
        self.command_preview.setPlainText(
            "./carv --src <source> --mode folders --out <output> "
            "--id <service-id> --make-image --fold <selected-folders>"
        )
        self.command_preview.setMaximumBlockCount(3)
        self.command_preview.setMinimumHeight(60)
        command_layout.addWidget(self.command_preview)

        execution_rail = QFrame()
        execution_rail.setObjectName("executionRail")
        execution_rail.setStyleSheet(
            f"QFrame#executionRail {{ background: #14191e; border: 1px solid {BORDER}; border-radius: 4px; }}"
        )
        button_row = QHBoxLayout(execution_rail)
        button_row.setContentsMargins(10, 8, 8, 8)
        button_row.setSpacing(10)

        self.plan_status = QLabel("●  INCOMPLETE")
        self.plan_status.setMaximumWidth(105)
        self.plan_status.setStyleSheet(
            f"color: {MUTED}; background: transparent; font-family: '{mono_font_family()}'; "
            "font-size: 10px; font-weight: 700; letter-spacing: 1px;"
        )
        self.plan_hint = QLabel("Missing: Service ID")
        self.plan_hint.setMaximumWidth(105)
        self.plan_hint.setStyleSheet(f"color: {MUTED}; background: transparent; font-size: 11px;")
        status_block = QVBoxLayout()
        status_block.setContentsMargins(0, 0, 0, 0)
        status_block.setSpacing(2)
        status_block.addWidget(self.plan_status)
        status_block.addWidget(self.plan_hint)
        button_row.addLayout(status_block)
        button_row.addStretch(1)
        self.start_button = StartRecoveryButton()
        self.start_button.setEnabled(False)
        self.start_button.clicked.connect(self._start_recovery)
        shadow = QGraphicsDropShadowEffect(self.start_button)
        shadow.setBlurRadius(10)
        shadow.setOffset(0, 1)
        shadow.setColor(QColor(40, 46, 52, 85))
        self.start_button.setGraphicsEffect(shadow)
        button_row.addWidget(self.start_button)
        command_layout.addWidget(execution_rail)

        layout.addWidget(command_box)
        self._refresh_plan_status()
        return panel

    def _on_selected_source_changed(self, source) -> None:
        self._selected_source = dict(source) if source else None
        self._source_selected = bool(source)
        self._auto_select_filesystem_for_source(self._selected_source)
        if self._manual_limit_bytes is not None and hasattr(self, "limit_bytes_slider"):
            self.limit_bytes_slider.blockSignals(True)
            self.limit_bytes_slider.setValue(
                self._slider_percent_for_manual_limit(self._manual_limit_bytes)
            )
            self.limit_bytes_slider.blockSignals(False)
        self._update_advanced_preview()
        self._refresh_setup_eta()
        self._refresh_plan_status()

    @staticmethod
    def _filesystem_choice_from_source(source) -> str:
        if not isinstance(source, dict):
            return "Auto detect"

        def recognized_choices(value: str) -> set[str]:
            lowered = str(value or "").strip().casefold()
            if not lowered or lowered in {"auto", "auto detect", "detecting", "unknown", "—"}:
                return set()
            choices = set()
            if (
                lowered == "hfs" or
                any(token in lowered for token in ("hfs+", "hfsplus", "hfsx", "apple_hfs"))
            ):
                choices.add("HFS+")
            if "ntfs" in lowered:
                choices.add("NTFS")
            if "exfat" in lowered:
                choices.add("exFAT")
            fat_text = lowered.replace("exfat", "")
            if "fat32" in fat_text or any(
                token == fat_text for token in ("vfat", "msdos", "fat")
            ):
                choices.add("FAT32")
            if "apfs" in lowered:
                choices.add("APFS")
            return choices

        for key in (
            "_interpreted_filesystem",
            "_preview_filesystem",
            "_filesystem",
            "fs",
        ):
            choices = recognized_choices(source.get(key))
            if len(choices) == 1:
                choice = next(iter(choices))
                return choice if choice in {"NTFS", "HFS+"} else "Auto detect"
            if len(choices) > 1:
                return "Auto detect"
        return "Auto detect"

    def _auto_select_filesystem_for_source(self, source) -> None:
        if not hasattr(self, "filesystem_combo"):
            return
        choice = self._filesystem_choice_from_source(source)
        if self.filesystem_combo.currentText() != choice:
            self.filesystem_combo.setCurrentText(choice)

    def _on_selected_output_changed(self, output_path: str, writable: bool = False) -> None:
        self._selected_output = str(output_path or "")
        self._output_selected = bool(output_path)
        self._output_writable = bool(output_path) and bool(writable)
        self._refresh_plan_status()

    def _on_folder_selection_changed(self, folders) -> None:
        self._selected_folders = list(folders or [])
        self._refresh_setup_eta()
        self._refresh_command_preview()
        self._refresh_plan_status()

    def _toggle_hypersafe_layout_panel(self, checked: bool) -> None:
        if checked:
            if hasattr(self, "image_first_check"):
                self.image_first_check.setChecked(True)
            if hasattr(self, "deep_image_check"):
                self.deep_image_check.setChecked(True)
        if hasattr(self, "hypersafe_layout_panel"):
            self.hypersafe_layout_panel.setVisible(bool(checked))
        self._refresh_hypersafe_strategy_ui(checked)

    def _refresh_hypersafe_strategy_ui(self, _checked: bool = False) -> None:
        enabled = bool(
            getattr(self, "hypersafe_enabled_check", None) is not None
            and self.hypersafe_enabled_check.isChecked()
        )
        radios = (
            getattr(self, "hypersafe_image_now_radio", None),
            getattr(self, "hypersafe_priority_radio", None),
            getattr(self, "hypersafe_tree_radio", None),
        )
        for radio in radios:
            if radio is not None:
                radio.setEnabled(enabled)

        priority_selected = bool(
            getattr(self, "hypersafe_priority_radio", None) is not None
            and self.hypersafe_priority_radio.isChecked()
        )
        tree_selected = bool(
            getattr(self, "hypersafe_tree_radio", None) is not None
            and self.hypersafe_tree_radio.isChecked()
        )
        image_only = self._image_only_requested()
        targeted_mode_active = enabled and (priority_selected or tree_selected)
        if hasattr(self, "mode_combo"):
            if targeted_mode_active:
                if image_only:
                    self.mode_combo.setCurrentText("Image only")
                else:
                    self.mode_combo.setCurrentText("Tree Recovery")
            self.mode_combo.setEnabled(not targeted_mode_active)
        if hasattr(self, "source_panel"):
            self.source_panel.set_wait_for_source_enabled(
                enabled
            )
        if hasattr(self, "hypersafe_priority_edit"):
            self.hypersafe_priority_edit.setVisible(priority_selected)
            self.hypersafe_priority_edit.setEnabled(enabled)
        if hasattr(self, "hypersafe_folder_fetch_button"):
            self.hypersafe_folder_fetch_button.setVisible(False)
        if hasattr(self, "hypersafe_tree_preview_hint"):
            self.hypersafe_tree_preview_hint.setVisible(enabled and tree_selected)

        if not enabled:
            title = "Hypersafe is not selected"
            detail = (
                "Confirm Hypersafe above to configure how Carv should react when "
                "the source becomes available."
            )
        elif priority_selected:
            title = "Find important folders first"
            if image_only:
                detail = (
                    "Enter any remembered part of each NTFS folder name. Carv ignores "
                    "letter case, images every match first, then completes the full "
                    "image without reconstructing files. Each line is an alternative."
                )
            else:
                detail = (
                    "Enter any remembered part of each NTFS folder name. Carv ignores "
                    "letter case, images every match first, then completes the full "
                    "image and reconstructs matching files as they become readable. "
                    "Each line is an alternative."
                )
        elif tree_selected:
            title = "Tree Recovery with Hypersafe"
            if image_only:
                detail = (
                    "Preview and select folders in Source above. Execute images their "
                    "extents first, then completes the full image without reconstructing files."
                )
            else:
                detail = (
                    "Preview and select folders in Source above. Execute images their "
                    "extents first, then completes the full image."
                )
        else:
            title = "Start imaging at first contact"
            detail = (
                "Wait if necessary, bind the source identity, and begin the complete "
                "image without pausing for folder selection."
            )
        if hasattr(self, "hypersafe_strategy_title"):
            self.hypersafe_strategy_title.setText(title)
        if hasattr(self, "hypersafe_strategy_detail"):
            self.hypersafe_strategy_detail.setText(detail)
        self._refresh_plan_status()

    def _image_only_requested(self) -> bool:
        return bool(
            getattr(self, "image_only_check", None) is not None and
            self.image_only_check.isChecked()
        )

    def _hypersafe_tree_recovery_requested(self) -> bool:
        return bool(
            getattr(self, "hypersafe_enabled_check", None) is not None
            and self.hypersafe_enabled_check.isChecked()
            and getattr(self, "hypersafe_tree_radio", None) is not None
            and self.hypersafe_tree_radio.isChecked()
        )

    def _hypersafe_immediate_requested(self) -> bool:
        return bool(
            getattr(self, "hypersafe_enabled_check", None) is not None
            and self.hypersafe_enabled_check.isChecked()
            and getattr(self, "hypersafe_image_now_radio", None) is not None
            and self.hypersafe_image_now_radio.isChecked()
        )

    def _hypersafe_priority_recovery_requested(self) -> bool:
        return bool(
            getattr(self, "hypersafe_enabled_check", None) is not None
            and self.hypersafe_enabled_check.isChecked()
            and getattr(self, "hypersafe_priority_radio", None) is not None
            and self.hypersafe_priority_radio.isChecked()
        )

    def _hypersafe_priority_terms(self) -> list[str]:
        editor = getattr(self, "hypersafe_priority_edit", None)
        return normalize_hypersafe_priority_terms(
            editor.toPlainText() if editor is not None else ""
        )

    def _hypersafe_priority_terms_error(self) -> str:
        terms = self._hypersafe_priority_terms()
        if not terms:
            return "folder search terms"
        if len(terms) > 64:
            return "max 64 folder search terms"
        if any(len(term.encode("utf-8")) >= 256 for term in terms):
            return "shorter folder search terms"
        return ""

    def _on_hypersafe_priority_terms_changed(self) -> None:
        self._refresh_setup_eta()
        self._refresh_plan_status()

    def _active_folder_scope_summary(self, empty_text: str) -> str:
        if self._hypersafe_priority_recovery_requested():
            terms = self._hypersafe_priority_terms()
            return (
                "Folder name contains: " + ", ".join(terms)
                if terms else "No folder search terms entered"
            )
        return ", ".join(self._selected_folders) or empty_text

    def _on_image_only_changed(self, checked: bool) -> None:
        if (
            hasattr(self, "mode_combo")
            and not self._syncing_image_only_mode
        ):
            current_mode = self.mode_combo.currentText()
            self._syncing_image_only_mode = True
            try:
                if checked and not self._mode_text_is_image_only(current_mode):
                    self._mode_before_image_only = current_mode or "Raw File Hunt"
                    self.mode_combo.setCurrentText("Image only")
                elif not checked and self._mode_text_is_image_only(current_mode):
                    restore_mode = self._mode_before_image_only
                    if (
                        self._mode_text_is_image_only(restore_mode)
                        or self.mode_combo.findText(restore_mode) < 0
                    ):
                        restore_mode = "Raw File Hunt"
                    self.mode_combo.setCurrentText(restore_mode)
            finally:
                self._syncing_image_only_mode = False
        if checked and hasattr(self, "image_first_check"):
            self.image_first_check.setChecked(True)
        self._refresh_hypersafe_strategy_ui()
        self._refresh_setup_eta()

    @staticmethod
    def _mode_text_is_raw_hunt(mode_text: str) -> bool:
        lowered = str(mode_text or "").strip().lower()
        return "raw file hunt" in lowered or "signature" in lowered

    @staticmethod
    def _mode_text_is_tree_recovery(mode_text: str) -> bool:
        lowered = str(mode_text or "").strip().lower()
        return "tree recovery" in lowered or "filesystem" in lowered

    @staticmethod
    def _mode_text_is_image_only(mode_text: str) -> bool:
        return "image only" in str(mode_text or "").strip().lower()

    def _current_mode_code(self) -> str:
        mode_text = self.mode_combo.currentText() if hasattr(self, "mode_combo") else ""
        if (
            self._mode_text_is_raw_hunt(mode_text)
            or self._mode_text_is_image_only(mode_text)
        ):
            return "all"
        if "name" in mode_text.lower():
            return "name"
        return "folders"

    def _refresh_setup_eta(self) -> None:
        if not hasattr(self, "eta_badge"):
            return
        if not self._selected_source:
            self.eta_badge.setText("READ ETA\nCHOOSE SOURCE")
            return

        if self._hypersafe_priority_recovery_requested():
            self.eta_badge.setText(
                "READ ETA\nMEASURED AFTER START"
                if not self._hypersafe_priority_terms_error()
                else "READ ETA\nENTER FOLDER NAMES"
            )
            return

        if self._hypersafe_tree_recovery_requested():
            self.eta_badge.setText(
                "IMAGE ETA\nMEASURED AFTER START"
                if self._selected_folders
                else "IMAGE ETA\nSELECT FOLDERS"
            )
            return

        if self._image_only_requested():
            self.eta_badge.setText("IMAGE ETA\nMEASURED AFTER START")
            return

        mode_text = self.mode_combo.currentText().lower() if hasattr(self, "mode_combo") else ""
        if self._mode_text_is_tree_recovery(mode_text):
            if self._selected_folders:
                self.eta_badge.setText("READ ETA\nMEASURED AFTER START")
            else:
                self.eta_badge.setText("READ ETA\nSELECT FOLDERS")
            return
        if "name" in mode_text:
            self.eta_badge.setText("READ ETA\nMEASURED AFTER START")
            return

        try:
            size_gib = int(self._selected_source.get("size_bytes") or 0) / (1024.0 ** 3)
        except (TypeError, ValueError):
            size_gib = 0.0
        media = str(self._selected_source.get("media") or "").upper()
        risk = str(self._selected_source.get("risk") or "normal")
        if "SSD" in media:
            speed_mib = 350.0
        elif "IMAGE" in media or "MOUNTED" in media:
            speed_mib = 220.0
        elif risk == "critical":
            speed_mib = 45.0
        elif risk == "caution":
            speed_mib = 70.0
        else:
            speed_mib = 110.0
        hours = (size_gib * 1024.0) / speed_mib / 3600.0 if size_gib > 0 else 0.0
        if hours >= 2.0:
            estimate = f"≈ {hours:.1f} HOURS"
        else:
            estimate = f"≈ {max(1, round(hours * 60))} MIN"
        self.eta_badge.setText(f"SEQUENTIAL ETA\n{estimate}")

    def _on_plan_tab_changed(self, index: int) -> None:
        if index == 1:
            self._filters_visited = True
        if hasattr(self, "mode_combo"):
            self._update_plan_mode_ui(self.mode_combo.currentText())
        self._refresh_plan_status()

    def _refresh_plan_status(self) -> None:
        if not hasattr(self, "plan_status"):
            return
        service_id = ""
        if hasattr(self, "service_id_combo"):
            service_id = self.service_id_combo.currentText().strip()
        mode_text = self.mode_combo.currentText() if hasattr(self, "mode_combo") else ""
        signature_mode = self._mode_text_is_raw_hunt(mode_text)
        filesystem_mode = self._mode_text_is_tree_recovery(mode_text)
        image_only = self._image_only_requested()
        hypersafe_immediate = self._hypersafe_immediate_requested()
        hypersafe_enabled = bool(
            getattr(self, "hypersafe_enabled_check", None) is not None
            and self.hypersafe_enabled_check.isChecked()
        )
        hypersafe_filesystem_ok = (
            not hypersafe_enabled
            or not hasattr(self, "filesystem_combo")
            or self.filesystem_combo.currentText().strip().casefold() != "hfs+"
        )
        hypersafe_tree_selected = self._hypersafe_tree_recovery_requested()
        hypersafe_priority_selected = self._hypersafe_priority_recovery_requested()
        hypersafe_priority_error = (
            self._hypersafe_priority_terms_error()
            if hypersafe_priority_selected else ""
        )
        hypersafe_targeted_selected = (
            hypersafe_tree_selected or hypersafe_priority_selected
        )
        selected_source_path = str((self._selected_source or {}).get("path") or "")
        hypersafe_source_ok = (
            not hypersafe_targeted_selected
            or (
                bool(selected_source_path)
                and not os.path.isdir(selected_source_path)
            )
        )
        hypersafe_strategy_ready = (
            not hypersafe_enabled
            or hypersafe_immediate
            or hypersafe_tree_selected
            or (hypersafe_priority_selected and not hypersafe_priority_error)
        )
        expected_source_strategy_ok = (
            not bool((self._selected_source or {}).get("is_expected_path"))
            or hypersafe_enabled
        )
        folder_scope_confirmed = (
            (image_only and not hypersafe_targeted_selected)
            or hypersafe_immediate
            or not filesystem_mode
            or (
                hypersafe_priority_selected
                and not hypersafe_priority_error
            )
            or (
                not hypersafe_priority_selected
                and bool(self._selected_folders)
            )
        )
        service_id_valid = bool(service_id) and service_id not in {".", ".."} and not any(
            separator and separator in service_id for separator in (os.sep, os.altsep, "\0")
        )
        date_valid = self._date_filter_is_valid()
        if hasattr(self, "workflow_marks"):
            def set_mark(key: str, done: bool, pending: str = "—") -> None:
                mark = self.workflow_marks[key]
                mark.setText("✓" if done else pending)
                mark.setStyleSheet(
                    f"color: {ACCENT if done else MUTED}; background: transparent; "
                    f"font-family: '{mono_font_family()}'; font-size: 11px; font-weight: 700;"
                )

            set_mark("service", service_id_valid)
            set_mark("source", self._source_selected)
            set_mark(
                "output",
                self._output_writable,
                "!" if self._output_selected else "—",
            )
        ready = (
            self._source_selected and
            self._output_selected and
            self._output_writable and
            service_id_valid and
            folder_scope_confirmed and
            date_valid and
            hypersafe_filesystem_ok and
            hypersafe_source_ok and
            hypersafe_strategy_ready and
            expected_source_strategy_ok
        )
        if self._process is not None and self._process.poll() is None:
            ready = False
        if self._source_test_thread is not None and self._source_test_thread.is_alive():
            ready = False
        hypersafe_running = (
            self._hypersafe_thread is not None and self._hypersafe_thread.is_alive()
        )
        if hypersafe_running:
            ready = False
        if hasattr(self, "hypersafe_folder_fetch_button"):
            source_path = str((self._selected_source or {}).get("path") or "")
            if hypersafe_running:
                self.hypersafe_folder_fetch_button.setEnabled(
                    self._hypersafe_process is not None and
                    self._hypersafe_process.poll() is None
                )
            else:
                self.hypersafe_folder_fetch_button.setEnabled(
                    hypersafe_enabled
                    and hypersafe_tree_selected
                    and self._source_selected
                    and self._output_writable
                    and service_id_valid
                    and filesystem_mode
                    and hypersafe_filesystem_ok
                    and bool(source_path)
                    and not os.path.isdir(source_path)
                    and not (
                        self._process is not None and self._process.poll() is None
                    )
                    and not (
                        self._source_test_thread is not None
                        and self._source_test_thread.is_alive()
                    )
                )
        if hasattr(self, "start_button"):
            self.start_button.setEnabled(ready)
        if ready:
            self.plan_status.setText("●  READY")
            self.plan_status.setStyleSheet(
                f"color: {ACCENT}; background: transparent; font-family: '{mono_font_family()}'; "
                "font-size: 10px; font-weight: 700; letter-spacing: 1px;"
            )
            self.plan_hint.setText("Final review")
        else:
            self.plan_status.setText("●  INCOMPLETE")
            self.plan_status.setStyleSheet(
                f"color: {MUTED}; background: transparent; font-family: '{mono_font_family()}'; "
                "font-size: 10px; font-weight: 700; letter-spacing: 1px;"
            )
            missing = []
            if not service_id:
                missing.append("Service ID")
            elif not service_id_valid:
                missing.append("valid Service ID")
            if not self._source_selected:
                missing.append("source")
            if not self._output_selected:
                missing.append("output")
            elif not self._output_writable:
                missing.append("writable output")
            if not folder_scope_confirmed:
                missing.append(
                    hypersafe_priority_error
                    if hypersafe_priority_selected and hypersafe_priority_error
                    else "preview + folders"
                )
            if not date_valid:
                missing.append("valid date range")
            if not hypersafe_filesystem_ok:
                missing.append("NTFS for Hypersafe")
            if not hypersafe_source_ok:
                missing.append("disk or image source for Hypersafe")
            if not hypersafe_strategy_ready:
                missing.append("completed Hypersafe strategy")
            if not expected_source_strategy_ok:
                missing.append("Image immediately for expected source")
            self.plan_hint.setText("Missing: " + (missing[0] if missing else "required input"))
        self._refresh_command_preview()

    def _date_filter_is_valid(self) -> bool:
        if not hasattr(self, "date_from_edit"):
            return True
        if self._hfs_pre_release_filters_disabled():
            return True
        parsed = []
        for value in (self.date_from_edit.text().strip(), self.date_to_edit.text().strip()):
            if not value:
                parsed.append(None)
                continue
            try:
                parsed.append(datetime.strptime(value, "%Y-%m-%d").date())
            except ValueError:
                return False
        return not (parsed[0] and parsed[1] and parsed[1] < parsed[0])

    def _refresh_command_preview(self, *_args) -> None:
        if not hasattr(self, "command_preview") or not hasattr(self, "mode_combo"):
            return
        source = self._selected_source.get("path", "<source>") if self._selected_source else "<source>"
        output = self._selected_output or "<output>"
        service_id = self.service_id_combo.currentText().strip() if hasattr(self, "service_id_combo") else ""
        service_id = service_id or "<service-id>"
        mode_text = self.mode_combo.currentText().lower()
        command_parts = []
        hypersafe_tree_recovery = self._hypersafe_tree_recovery_requested()
        hypersafe_priority_recovery = self._hypersafe_priority_recovery_requested()
        hypersafe_targeted_recovery = (
            hypersafe_tree_recovery or hypersafe_priority_recovery
        )
        wait_for_new_source = bool(
            (self._selected_source or {}).get("wait_for_new_source")
        )
        if source.startswith("/dev/") or wait_for_new_source:
            command_parts.append("sudo")
        command_parts.extend(["./carv", "--src", source, "--out", output, "--id", service_id])
        filter_parts = []
        filters_available = not self._hfs_pre_release_filters_disabled()
        image_only = self._image_only_requested()
        hypersafe_immediate = self._hypersafe_immediate_requested()
        if hypersafe_immediate:
            mode = "all"
            command_parts.extend(["--hypersafe", "immediate"])
        elif hypersafe_targeted_recovery:
            mode = "folders"
            if hypersafe_priority_recovery:
                priority_terms = self._hypersafe_priority_terms()
                folders = (
                    encode_folder_scope_paths(priority_terms)
                    if priority_terms
                    else "<folder-search-terms>"
                )
            else:
                folders = (
                    encode_folder_scope_paths(self._selected_folders)
                    if self._selected_folders
                    else "<selected-folders>"
                )
            filter_parts.extend(["--fold", folders])
            if filters_available and not image_only:
                filter_parts.extend(self._selected_file_type_filter_parts())
            command_parts.append("--hypersafe-recover")
        elif image_only:
            mode = "all"
        elif self._mode_text_is_raw_hunt(mode_text):
            mode = "all"
            if filters_available:
                filter_parts.extend(self._selected_file_type_filter_parts())
        elif "name" in mode_text:
            mode = "name"
        else:
            mode = "folders"
            if hypersafe_priority_recovery:
                priority_terms = self._hypersafe_priority_terms()
                folders = (
                    encode_folder_scope_paths(priority_terms)
                    if priority_terms
                    else "<folder-search-terms>"
                )
            else:
                folders = (
                    encode_folder_scope_paths(self._selected_folders)
                    if self._selected_folders
                    else "<selected-folders>"
                )
            filter_parts.extend(["--fold", folders])
            if filters_available:
                filter_parts.extend(self._selected_file_type_filter_parts())
        if mode != "name" and not image_only and not hypersafe_immediate and filters_available:
            date_from = self.date_from_edit.text().strip().replace("-", "") if hasattr(self, "date_from_edit") else ""
            date_to = self.date_to_edit.text().strip().replace("-", "") if hasattr(self, "date_to_edit") else ""
            if len(date_from) == 8:
                date_value = date_from if len(date_to) != 8 or date_to == date_from else f"{date_from}-{date_to}"
                filter_parts.extend(["--date", date_value])
            if hasattr(self, "file_state_radios"):
                if self.file_state_radios["Live"].isChecked():
                    filter_parts.extend(["--del", "0"])
                elif self.file_state_radios["Deleted"].isChecked():
                    filter_parts.extend(["--del", "1"])

        command_parts.extend(["--mode", mode])
        advanced_parts = []
        if hasattr(self, "filesystem_combo"):
            filesystem = self.filesystem_combo.currentText().strip().lower()
            filesystem_values = {
                "auto detect": "auto",
                "ntfs": "ntfs",
                "hfs+": "hfsplus",
            }
            filesystem_value = filesystem_values.get(filesystem, filesystem)
            if filesystem_value != "auto":
                advanced_parts.extend(["--filesys", filesystem_value])
        source_size = int(self._selected_source.get("size_bytes") or 0) if self._selected_source else 0
        start_bytes = 0
        if self._manual_start_bytes is not None:
            start_bytes = max(0, int(self._manual_start_bytes))
            if start_bytes > 0:
                advanced_parts.extend(["--start", str(start_bytes)])
        elif hasattr(self, "start_position_slider"):
            start_ratio = self.start_position_slider.value() / max(1, self.start_position_slider.maximum())
            if start_ratio > 0:
                if source_size > 0:
                    start_bytes = round(source_size * start_ratio)
                    advanced_parts.extend(["--start", str(start_bytes)])
                else:
                    advanced_parts.extend([
                        "--start",
                        f"<{self.start_position_slider.value()}%-of-source-bytes>",
                    ])

        if self._manual_limit_bytes is not None:
            limit_bytes = max(0, int(self._manual_limit_bytes))
            if limit_bytes > 0:
                advanced_parts.extend(["--limit", str(limit_bytes)])
        elif hasattr(self, "limit_bytes_slider"):
            limit_ratio = self.limit_bytes_slider.value() / max(1, self.limit_bytes_slider.maximum())
            if 0 < limit_ratio < 1:
                if source_size > 0:
                    remaining_bytes = max(0, source_size - start_bytes)
                    advanced_parts.extend(["--limit", str(round(remaining_bytes * limit_ratio))])
                else:
                    advanced_parts.extend([
                        "--limit",
                        f"<{self.limit_bytes_slider.value()}%-of-remaining-source-bytes>",
                    ])

        if image_only and (hypersafe_immediate or hypersafe_targeted_recovery):
            command_parts.append("--image-only")
        elif not hypersafe_immediate and not hypersafe_targeted_recovery:
            if image_only:
                command_parts.extend(["--make-image", "--image-only"])
                if hasattr(self, "deep_image_check") and self.deep_image_check.isChecked():
                    command_parts.extend(["--ddrescue-mode", "thorough"])
            elif hasattr(self, "image_first_check") and self.image_first_check.isChecked():
                command_parts.append("--make-image")
                if hasattr(self, "deep_image_check") and self.deep_image_check.isChecked():
                    command_parts.extend(["--ddrescue-mode", "thorough"])
        command_parts.extend(filter_parts)
        command_parts.extend(advanced_parts)
        self.command_preview.setPlainText(" ".join(shlex.quote(part) for part in command_parts))

    def _hfs_pre_release_filters_disabled(self) -> bool:
        return bool(
            hasattr(self, "filesystem_combo") and
            self.filesystem_combo.currentText().strip().casefold() == "hfs+"
        )

    def _update_hfs_filter_availability(self, filesystem_text: str = "") -> None:
        unavailable = str(filesystem_text or "").strip().casefold() == "hfs+"
        tooltip = "Not available in pre release" if unavailable else ""

        filter_tabs = getattr(self, "type_filter_tabs", None)
        if filter_tabs is not None:
            filter_tabs.setEnabled(not unavailable)

        tooltip_widgets = []
        if filter_tabs is not None:
            tooltip_widgets.append(filter_tabs)
            tooltip_widgets.extend(filter_tabs.findChildren(QWidget))

        for edit_name in ("date_from_edit", "date_to_edit"):
            edit = getattr(self, edit_name, None)
            if edit is not None:
                edit.setEnabled(not unavailable)
                tooltip_widgets.append(edit)

        for label_name in (
            "date_filter_label",
            "date_filter_separator",
            "file_state_label",
        ):
            label = getattr(self, label_name, None)
            if label is not None:
                label.setEnabled(not unavailable)
                tooltip_widgets.append(label)

        for option in getattr(self, "file_state_radios", {}).values():
            option.setEnabled(not unavailable)
            tooltip_widgets.append(option)

        saved_tooltips = getattr(self, "_hfs_filter_saved_tooltips", {})
        if unavailable:
            if not saved_tooltips:
                saved_tooltips = {
                    widget: widget.toolTip()
                    for widget in tooltip_widgets
                }
                self._hfs_filter_saved_tooltips = saved_tooltips
            for widget in tooltip_widgets:
                widget.setToolTip(tooltip)
        else:
            for widget, original_tooltip in saved_tooltips.items():
                widget.setToolTip(original_tooltip)
            self._hfs_filter_saved_tooltips = {}

        self._refresh_command_preview()
        self._refresh_plan_status()

    def _run_directory(self) -> Path | None:
        service_id = self.service_id_combo.currentText().strip() if hasattr(self, "service_id_combo") else ""
        output = str(self._selected_output or "").strip()
        if not service_id or not output:
            return None
        output_path = Path(output).expanduser()
        return output_path if output_path.name == service_id else output_path / service_id

    def _filesystem_override_parts(self) -> list[str]:
        if not hasattr(self, "filesystem_combo"):
            return []
        filesystem = self.filesystem_combo.currentText().strip().lower()
        filesystem_values = {
            "auto detect": "auto",
            "ntfs": "ntfs",
            "hfs+": "hfsplus",
        }
        filesystem_value = filesystem_values.get(filesystem, filesystem)
        return ["--filesys", filesystem_value] if filesystem_value != "auto" else []

    def _open_path_in_file_manager(self, target: Path, title: str = "Open folder") -> bool:
        try:
            if not target or not target.is_dir():
                return False
        except (OSError, ValueError):
            return False
        if sys.platform == "darwin":
            command = ["open", str(target)]
        elif sys.platform.startswith("linux"):
            command = ["xdg-open", str(target)]
        else:
            QMessageBox.warning(
                self,
                title,
                f"Opening folders is not implemented for {sys.platform}.",
            )
            return False
        try:
            subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=(sys.platform != "darwin"),
            )
            return True
        except OSError as exc:
            QMessageBox.warning(self, title, f"Could not open the folder:\n\n{target}\n\n{exc}")
            return False

    @staticmethod
    def _jpeg_test_image_paths(test_dir: Path) -> list[Path]:
        jpeg_suffixes = {".jpg", ".jpeg", ".jpe"}

        try:
            return sorted(
                [
                    path
                    for path in test_dir.iterdir()
                    if path.is_file() and path.suffix.lower() in jpeg_suffixes
                ],
                key=lambda path: path.name.casefold(),
            )
        except (OSError, ValueError):
            return []

    def _open_images_in_default_viewer(self, image_paths: list[Path], title: str = "Open images") -> bool:
        paths = [Path(path) for path in image_paths if path]
        if not paths:
            return False

        try:
            if sys.platform == "darwin":
                command = ["open"] + [str(path) for path in paths]
                subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True

            if sys.platform.startswith("linux"):
                gio = shutil.which("gio")
                if gio:
                    subprocess.Popen(
                        [gio, "open"] + [str(path) for path in paths],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    return True
                opener = shutil.which("xdg-open")
                if opener:
                    for path in paths:
                        subprocess.Popen(
                            [opener, str(path)],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            start_new_session=True,
                        )
                    return True

            QMessageBox.warning(
                self,
                title,
                f"Opening images is not implemented for {sys.platform}.",
            )
            return False
        except OSError as exc:
            QMessageBox.warning(
                self,
                title,
                f"Could not open the recovered images:\n\n{exc}",
            )
            return False

    @staticmethod
    def _path_exists(path: Path) -> bool:
        try:
            return path.exists()
        except (OSError, ValueError):
            return False

    @staticmethod
    def _path_stat(path: Path):
        try:
            return path.stat()
        except (OSError, ValueError):
            return None

    def _state_path_is_current_run(self, path: Path) -> bool:
        stat = self._path_stat(path)
        return bool(
            stat is not None
            and (
                not self._run_started_wall_time
                or stat.st_mtime >= self._run_started_wall_time - 1.0
            )
        )

    @staticmethod
    def _read_state_file(path: Path) -> dict:
        values = {}
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return values
        for line in lines:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            if "=" in text:
                key, value = text.split("=", 1)
            elif "\t" in text:
                key, value = text.split("\t", 1)
            else:
                continue
            values[key.strip()] = value.strip()
        return values

    @staticmethod
    def _run_dir_is_jpeg_test_only(run_dir: Path) -> bool:
        try:
            if not run_dir.is_dir():
                return False
        except (OSError, ValueError):
            return False

        state_dir = run_dir / "state"
        recovered_dir = run_dir / "recovered"
        real_run_state = (
            state_dir / "scan_state.txt",
            state_dir / "raw_all_stage.txt",
        )
        if any(CarvGuiWindow._path_exists(path) for path in real_run_state):
            return False

        allowed_top_level = {
            "recovered",
            "state",
            ".carv-run.lock",
        }
        try:
            top_entries = [entry for entry in run_dir.iterdir() if entry.name not in {".", ".."}]
        except OSError:
            return False
        if not top_entries:
            return False
        if any(entry.name not in allowed_top_level for entry in top_entries):
            return False

        has_test_output = False
        if recovered_dir.exists():
            try:
                recovered_entries = list(recovered_dir.iterdir())
            except OSError:
                return False
            for entry in recovered_entries:
                if entry.name != "test" or not entry.is_dir():
                    return False
                has_test_output = True

        allowed_state_files = {
            "gui_jpeg_test_only.txt",
            "hfsplus_recovery.lock",
            "hfsplus_recovery_progress.txt",
            "hfsplus_recovery_failures.tsv",
            "last_bad_read.txt",
            "read_errors.tsv",
            "read_trouble_map.tsv",
            "recovered_outputs.tsv",
        }
        has_test_marker = False
        if state_dir.exists():
            try:
                state_entries = list(state_dir.iterdir())
            except OSError:
                return False
            for entry in state_entries:
                if entry.name == "gui_jpeg_test_only.txt":
                    has_test_marker = True
                if entry.is_dir() or entry.name not in allowed_state_files:
                    return False

        return has_test_output or has_test_marker

    @staticmethod
    def _active_run_lock_owner(run_dir: Path) -> tuple[bool, str]:
        lock_paths = (
            run_dir / ".carv-run.lock",
            Path(str(run_dir) + ".carv-run.lock"),
        )
        for lock_path in lock_paths:
            active, owner = CarvGuiWindow._active_run_lock_owner_at(lock_path)
            if active:
                return active, owner
        return False, ""

    @staticmethod
    def _active_run_lock_owner_at(lock_path: Path) -> tuple[bool, str]:
        descriptor = None
        try:
            descriptor = os.open(str(lock_path), os.O_RDWR)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                try:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    owner = os.read(descriptor, 1024).decode("utf-8", errors="replace").strip()
                except OSError:
                    owner = ""
                return True, owner
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            return False, ""
        except FileNotFoundError:
            return False, ""
        except OSError as exc:
            # If ownership cannot be verified, do not permit a folder rename
            # that could split an active recovery across two run directories.
            return True, f"lock status unavailable: {exc}"
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _resolve_existing_run(self, run_dir: Path) -> str | None:
        run_active, lock_owner = self._active_run_lock_owner(run_dir)
        if run_active:
            owner_detail = f"\n\nOwner: {lock_owner}" if lock_owner else ""
            QMessageBox.warning(
                self,
                "Recovery already active",
                "This Service ID is already owned by a running Carv/ddrescue process. "
                "Stop or kill that recovery before choosing Resume or Archive + restart."
                f"\n\n{run_dir}{owner_detail}",
            )
            return None
        if not run_dir.exists():
            return "new"
        try:
            if not any(run_dir.iterdir()):
                return "new"
        except OSError:
            pass
        if self._run_dir_is_jpeg_test_only(run_dir):
            return "new"
        state = self._read_state_file(run_dir / "state" / "scan_state.txt")
        status = "completed" if state.get("completed") == "1" else "incomplete"
        box = QMessageBox(self)
        box.setWindowTitle("Existing recovery run")
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(f"A {status} run already exists for this Service ID.")
        box.setInformativeText(
            f"{run_dir}\n\nResume keeps its state. Archive + restart preserves the entire old run folder "
            "and creates a clean run with the same Service ID."
        )
        resume_button = box.addButton("Resume", QMessageBox.ButtonRole.AcceptRole)
        restart_button = box.addButton("Archive + restart", QMessageBox.ButtonRole.DestructiveRole)
        cancel_button = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(resume_button)
        box.setEscapeButton(cancel_button)
        box.exec()
        clicked = box.clickedButton()
        if clicked is resume_button:
            saved_source = str(state.get("source_path") or "").strip()
            saved_mode = str(state.get("scan_mode") or "").strip()
            current_source = str(self._selected_source.get("path") or "") if self._selected_source else ""
            current_mode = self._current_mode_code()
            mismatch = []
            if saved_source and current_source and saved_source != current_source:
                mismatch.append(f"Source changed:\n  saved: {saved_source}\n  current: {current_source}")
            if saved_mode and saved_mode != current_mode:
                mismatch.append(f"Mode changed: saved {saved_mode}, current {current_mode}")
            if mismatch:
                answer = QMessageBox.warning(
                    self,
                    "Resume mismatch",
                    "The current setup does not match the saved run state.\n\n" + "\n\n".join(mismatch)
                    + "\n\nResume only if you have verified that this is the same recovery source.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if answer != QMessageBox.StandardButton.Yes:
                    return None
            return "resume"
        if clicked is restart_button:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive = run_dir.with_name(f"{run_dir.name}__archived_{stamp}")
            counter = 2
            while archive.exists():
                archive = run_dir.with_name(f"{run_dir.name}__archived_{stamp}_{counter}")
                counter += 1
            try:
                run_dir.rename(archive)
            except OSError as exc:
                QMessageBox.warning(self, "Archive failed", f"Could not archive the old run:\n\n{exc}")
                return None
            return "restart"
        return None

    def _sudo_execution(
        self,
        command_parts,
        *,
        title: str = "Start recovery",
        message: str = "Carv needs permission to read the selected source.",
        button_text: str = "Start recovery",
    ):
        parts = list(command_parts)
        if not parts or parts[0] != "sudo":
            return parts, None, ""
        env, error = sudo_askpass_environment(
            title,
            message,
            button_text,
        )
        if error:
            return [], None, error
        # Authenticate and exec the real worker in one sudo transaction.
        # The askpass helper has its own timeout, so an inaccessible desktop
        # dialog cannot leave the run monitor in STARTING indefinitely.
        return ["sudo", "-A"] + parts[1:], env, ""

    @staticmethod
    def _utf8_execution_environment(environment=None) -> dict:
        result = dict(os.environ if environment is None else environment)
        result.setdefault("PYTHONIOENCODING", "utf-8")
        result.setdefault("PYTHONUTF8", "1")
        locale_name = str(
            result.get("LC_ALL")
            or result.get("LC_CTYPE")
            or result.get("LANG")
            or ""
        )
        if "utf-8" not in locale_name.lower() and "utf8" not in locale_name.lower():
            utf8_locale = "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8"
            result.pop("LC_ALL", None)
            result["LC_CTYPE"] = utf8_locale
            result["LANG"] = utf8_locale
        return result

    def _signal_auxiliary_process(
        self,
        process,
        started_with_sudo: bool,
        sig: signal.Signals | int,
        title: str,
        activity_name: str,
    ) -> bool:
        if process is None or process.poll() is not None:
            return True
        try:
            if started_with_sudo:
                signal_name = "-KILL" if int(sig) == int(signal.SIGKILL) else "-TERM"
                helper = app_runtime_root() / "scripts" / "carv_gui_askpass.py"
                env = os.environ.copy()
                env.update({
                    "SUDO_ASKPASS": str(helper),
                    "CARV_ASKPASS_TITLE": title,
                    "CARV_ASKPASS_PROMPT": f"Authenticate to stop {activity_name}.",
                    "CARV_ASKPASS_OK": title,
                    "CARV_ASKPASS_CANCEL": "Cancel",
                })
                result = subprocess.run(
                    ["sudo", "-A", "kill", signal_name, "--", f"-{process.pid}"],
                    cwd=str(app_runtime_root()),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
                if result.returncode != 0:
                    raise OSError((result.stderr or result.stdout or "sudo kill failed").strip())
            else:
                os.killpg(process.pid, int(sig))
            return True
        except (OSError, subprocess.TimeoutExpired) as exc:
            QMessageBox.warning(self, title, f"Could not signal {activity_name}:\n\n{exc}")
            return False

    @staticmethod
    def _bounded_auxiliary_output(process, limit: int = 256 * 1024) -> str:
        """Drain child output without letting a long ddrescue run fill RAM."""
        if process is None or process.stdout is None:
            if process is not None:
                process.wait()
            return ""
        tail = ""
        while True:
            chunk = process.stdout.read(4096)
            if not chunk:
                break
            tail = (tail + chunk)[-limit:]
        process.wait()
        return tail

    def _signal_source_test_process(self, sig: signal.Signals | int, title: str) -> bool:
        return self._signal_auxiliary_process(
            self._source_test_process,
            self._source_test_started_with_sudo,
            sig,
            title,
            "the source JPEG test",
        )

    def _signal_hypersafe_process(self, sig: signal.Signals | int, title: str) -> bool:
        return self._signal_auxiliary_process(
            self._hypersafe_process,
            self._hypersafe_started_with_sudo,
            sig,
            title,
            "the Hypersafe folder fetch",
        )

    def _run_source_jpeg_test(self) -> None:
        active_process = self._process
        if active_process is not None and active_process.poll() is None:
            QMessageBox.information(
                self,
                "JPEG test",
                "A recovery process is already active. Stop or finish it before starting a source test.",
            )
            return
        if self._source_test_thread is not None and self._source_test_thread.is_alive():
            QMessageBox.information(self, "JPEG test", "A JPEG test is already running.")
            return
        if not self._selected_source or not str(self._selected_source.get("path") or "").strip():
            QMessageBox.warning(self, "JPEG test", "Choose a source first.")
            return
        service_id = self.service_id_combo.currentText().strip() if hasattr(self, "service_id_combo") else ""
        if not service_id:
            QMessageBox.warning(self, "JPEG test", "Choose a Service ID first.")
            return
        if not self._selected_output:
            QMessageBox.warning(self, "JPEG test", "Choose an output folder first.")
            return
        if not self._output_writable:
            QMessageBox.warning(self, "JPEG test", "The selected output folder is not writable.")
            return

        run_dir = self._run_directory()
        if run_dir is None:
            QMessageBox.warning(self, "JPEG test", "The run folder could not be resolved.")
            return
        try:
            run_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            QMessageBox.warning(self, "JPEG test", f"Could not create the run folder:\n\n{exc}")
            return

        source_path = str(self._selected_source.get("path") or "").strip()
        output_root = str(self._selected_output or "").strip()
        command_parts = []
        if source_path.startswith("/dev/"):
            command_parts.append("sudo")
        command_parts.extend([
            "./carv",
            "--src",
            source_path,
            "--out",
            output_root,
            "--id",
            service_id,
            "--mode",
            "folders",
            "--test-jpegs",
            "10",
        ])
        command_parts.extend(self._filesystem_override_parts())
        execution_parts, execution_env, error = self._sudo_execution(
            command_parts,
            title="JPEG test",
            message="Carv needs permission to read filesystem metadata and copy test JPEGs from this source.",
            button_text="Run JPEG test",
        )
        if error:
            QMessageBox.warning(self, "JPEG test", error)
            return
        execution_env = self._utf8_execution_environment(execution_env)
        test_dir = run_dir / "recovered" / "test"
        try:
            marker_dir = run_dir / "state"
            marker_dir.mkdir(parents=True, exist_ok=True)
            (marker_dir / "gui_jpeg_test_only.txt").write_text(
                "created_by=carv_gui_jpeg_test\n",
                encoding="utf-8",
            )
        except OSError:
            pass

        self.source_panel.stop_folder_discovery_for_recovery()
        self.source_panel.set_test_recovery_running(True)
        self.source_panel.source_meta.setText("JPEG TEST | STARTING")
        self._source_test_spinner_index = 0
        self._source_test_process = None
        self._source_test_started_with_sudo = bool(execution_parts) and execution_parts[0] == "sudo"
        self._source_test_result = None
        if hasattr(self, "run_event_log"):
            self._append_event_command(command_parts)

        def worker() -> None:
            process = None
            try:
                kwargs = {
                    "cwd": str(app_runtime_root()),
                    "env": execution_env,
                    "stdin": subprocess.DEVNULL,
                    "stdout": subprocess.PIPE,
                    "stderr": subprocess.STDOUT,
                    "text": True,
                    "encoding": "utf-8",
                    "errors": "replace",
                }
                if os.name == "posix":
                    kwargs["start_new_session"] = True
                process = subprocess.Popen(execution_parts, **kwargs)
                self._source_test_process = process
                stdout = self._bounded_auxiliary_output(process)
                self._source_test_result = {
                    "returncode": process.returncode,
                    "output": stdout or "",
                    "test_dir": test_dir,
                }
            except OSError as exc:
                self._source_test_result = {
                    "returncode": -1,
                    "output": f"Could not start carv: {exc}",
                    "test_dir": test_dir,
                }
            finally:
                if self._source_test_process is process:
                    self._source_test_process = None
                    self._source_test_started_with_sudo = False

        self._source_test_thread = threading.Thread(
            target=worker,
            name="carv-source-jpeg-test",
            daemon=True,
        )
        self._source_test_thread.start()
        self._source_test_timer.start()

    def _poll_source_jpeg_test(self) -> None:
        thread = self._source_test_thread
        if thread is not None and thread.is_alive():
            spinner = "|/-\\"[self._source_test_spinner_index % 4]
            self._source_test_spinner_index = (self._source_test_spinner_index + 1) % 4
            if hasattr(self, "source_panel"):
                self.source_panel.source_meta.setText(f"JPEG TEST {spinner} METADATA RECOVERY")
            return

        self._source_test_timer.stop()
        self._source_test_thread = None
        result = self._source_test_result
        self._source_test_result = None
        if hasattr(self, "source_panel"):
            self.source_panel.set_test_recovery_running(False)
            self.source_panel._restore_source_meta()
        self._refresh_plan_status()
        if result is None:
            return

        output = str(result.get("output") or "")
        if output and hasattr(self, "run_event_log"):
            self._append_event_log(output.rstrip())
        test_dir = result.get("test_dir")
        test_path = Path(test_dir) if test_dir else None
        returncode = int(result.get("returncode") or 0)
        if returncode == 0 and test_path is not None and test_path.is_dir():
            image_paths = self._jpeg_test_image_paths(test_path)
            opened = self._open_images_in_default_viewer(image_paths[:1], "JPEG test")
            if not opened:
                QMessageBox.information(
                    self,
                    "JPEG test complete",
                    f"Recovered test JPEGs into:\n\n{test_path}",
                )
            return

        cleaned = ANSI_ESCAPE_RE.sub("", output)
        cleaned = TERMINAL_CONTROL_RE.sub("", cleaned)
        lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
        tail = "\n".join(lines[-12:]) if lines else "No output from carv."
        QMessageBox.warning(
            self,
            "JPEG test failed",
            "The metadata JPEG test did not produce a usable test folder.\n\n" + tail,
        )

    def _run_hypersafe_folder_fetch(self) -> None:
        if self._process is not None and self._process.poll() is None:
            QMessageBox.information(
                self, "Hypersafe folder fetch", "A recovery process is already active."
            )
            return
        if self._source_test_thread is not None and self._source_test_thread.is_alive():
            QMessageBox.information(
                self, "Hypersafe folder fetch", "Wait for the JPEG test to finish first."
            )
            return
        if self._hypersafe_thread is not None and self._hypersafe_thread.is_alive():
            sig = signal.SIGTERM if self._hypersafe_stop_stage == 0 else signal.SIGKILL
            if self._signal_hypersafe_process(
                    sig,
                    "Stop Hypersafe fetch" if self._hypersafe_stop_stage == 0
                    else "Kill Hypersafe fetch"):
                self._hypersafe_stop_stage += 1
                self.hypersafe_folder_fetch_button.setText(
                    "KILL HYPERSAFE FETCH" if self._hypersafe_stop_stage == 1
                    else "KILL SENT · WAITING…"
                )
            return
        if not self._selected_source or not str(self._selected_source.get("path") or "").strip():
            QMessageBox.warning(self, "Hypersafe folder fetch", "Choose a source first.")
            return
        service_id = self.service_id_combo.currentText().strip()
        service_id_valid = bool(service_id) and service_id not in {".", ".."} and not any(
            separator and separator in service_id
            for separator in (os.sep, os.altsep, "\0")
        )
        if not service_id_valid:
            QMessageBox.warning(
                self, "Hypersafe folder fetch", "Choose a valid Service ID first."
            )
            return
        if not self._mode_text_is_tree_recovery(self.mode_combo.currentText()):
            QMessageBox.warning(
                self,
                "Hypersafe folder fetch",
                "Choose Tree Recovery before fetching the MFT preview.",
            )
            return
        if (
            hasattr(self, "filesystem_combo") and
            self.filesystem_combo.currentText().strip().casefold() == "hfs+"
        ):
            QMessageBox.warning(
                self,
                "Hypersafe folder fetch",
                "This early Hypersafe preview currently supports NTFS only.",
            )
            return
        if not self._selected_output or not self._output_writable:
            QMessageBox.warning(
                self, "Hypersafe folder fetch", "Choose a writable output folder first."
            )
            return
        run_dir = self._run_directory()
        if run_dir is None:
            QMessageBox.warning(
                self, "Hypersafe folder fetch", "The run folder could not be resolved."
            )
            return
        run_active, lock_owner = self._active_run_lock_owner(run_dir)
        if run_active:
            detail = f"\n\nOwner: {lock_owner}" if lock_owner else ""
            QMessageBox.warning(
                self,
                "Hypersafe folder fetch",
                f"This Service ID is already active. Stop that process first.{detail}",
            )
            return
        try:
            (run_dir / "state").mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            QMessageBox.warning(
                self,
                "Hypersafe folder fetch",
                f"Could not create the run folder:\n\n{exc}",
            )
            return

        source_path = str(self._selected_source.get("path") or "").strip()
        command_parts = []
        if source_path.startswith("/dev/"):
            command_parts.append("sudo")
        command_parts.extend([
            "./carv",
            "--src", source_path,
            "--out", str(self._selected_output),
            "--id", service_id,
            "--filesys", "ntfs",
            "--hypersafe-folder-fetch",
        ])
        execution_parts, execution_env, error = self._sudo_execution(
            command_parts,
            title="Hypersafe folder fetch",
            message=(
                "Carv needs permission to let ddrescue copy disk headers and NTFS $MFT "
                "into a sparse preview image."
            ),
            button_text="Fetch MFT preview",
        )
        if error:
            QMessageBox.warning(self, "Hypersafe folder fetch", error)
            return
        execution_env = self._utf8_execution_environment(execution_env)
        self.source_panel.stop_folder_discovery_for_recovery()
        self.source_panel.test_jpegs_button.setEnabled(False)
        self.source_panel.source_meta.setText("HYPERSAFE | STARTING DDRESCUE")
        self._hypersafe_spinner_index = 0
        self._hypersafe_run_dir = run_dir
        self._hypersafe_process = None
        self._hypersafe_started_with_sudo = bool(execution_parts) and execution_parts[0] == "sudo"
        self._hypersafe_result = None
        self._hypersafe_stop_stage = 0
        self.hypersafe_folder_fetch_button.setText("HYPERSAFE FETCH RUNNING…")
        self.hypersafe_folder_fetch_button.setEnabled(False)
        if hasattr(self, "run_event_log"):
            self._append_event_command(command_parts)

        def worker() -> None:
            process = None
            try:
                kwargs = {
                    "cwd": str(app_runtime_root()),
                    "env": execution_env,
                    "stdin": subprocess.DEVNULL,
                    "stdout": subprocess.PIPE,
                    "stderr": subprocess.STDOUT,
                    "text": True,
                    "encoding": "utf-8",
                    "errors": "replace",
                }
                if os.name == "posix":
                    kwargs["start_new_session"] = True
                process = subprocess.Popen(execution_parts, **kwargs)
                self._hypersafe_process = process
                stdout = self._bounded_auxiliary_output(process)
                self._hypersafe_result = {
                    "returncode": process.returncode,
                    "output": stdout or "",
                    "run_dir": run_dir,
                }
            except OSError as exc:
                self._hypersafe_result = {
                    "returncode": -1,
                    "output": f"Could not start carv: {exc}",
                    "run_dir": run_dir,
                }
            finally:
                if self._hypersafe_process is process:
                    self._hypersafe_process = None
                    self._hypersafe_started_with_sudo = False

        self._hypersafe_thread = threading.Thread(
            target=worker,
            name="carv-hypersafe-folder-fetch",
            daemon=True,
        )
        self._hypersafe_thread.start()
        self._hypersafe_timer.start()
        self._refresh_plan_status()

    def _poll_hypersafe_folder_fetch(self) -> None:
        thread = self._hypersafe_thread
        if thread is not None and thread.is_alive():
            spinner = "|/-\\"[self._hypersafe_spinner_index % 4]
            self._hypersafe_spinner_index = (self._hypersafe_spinner_index + 1) % 4
            supervisor_state = self._read_state_file(
                Path(self._hypersafe_run_dir) / "state" / "ddrescue_supervisor.txt"
            ) if self._hypersafe_run_dir else {}
            if str(supervisor_state.get("status") or "").strip().lower() == "kernel_io_hang":
                self._kernel_reboot_required = True
                phase = str(
                    supervisor_state.get("phase") or "Hypersafe metadata fetch"
                ).strip()
                self.source_panel.source_meta.setText(
                    f"KERNEL I/O HANG · {phase} · MAP SAVED · REBOOT REQUIRED"
                )
                self.hypersafe_folder_fetch_button.setText("REBOOT REQUIRED")
                self.hypersafe_folder_fetch_button.setEnabled(False)
                self._hypersafe_timer.stop()
                return
            state = self._read_state_file(
                Path(self._hypersafe_run_dir) / "state" / "hypersafe_bootstrap.txt"
            ) if self._hypersafe_run_dir else {}
            stage = str(state.get("status") or "acquiring metadata").replace("_", " ").upper()
            detail = str(state.get("detail") or "").strip()
            self.source_panel.source_meta.setText(
                f"HYPERSAFE {spinner} {stage}" + (f" · {detail}" if detail else "")
            )
            self.hypersafe_folder_fetch_button.setEnabled(
                self._hypersafe_process is not None and
                self._hypersafe_process.poll() is None
            )
            if self._hypersafe_stop_stage == 0:
                self.hypersafe_folder_fetch_button.setText("STOP HYPERSAFE FETCH")
            return

        self._hypersafe_timer.stop()
        self._hypersafe_thread = None
        stop_requested = self._hypersafe_stop_stage > 0
        self._hypersafe_stop_stage = 0
        result = self._hypersafe_result
        self._hypersafe_result = None
        self.hypersafe_folder_fetch_button.setText("Fetch MFT and show folder tree")
        self.source_panel.test_jpegs_button.setEnabled(self._selected_source is not None)
        self._refresh_plan_status()
        if result is None:
            self.source_panel._restore_source_meta()
            return

        output = str(result.get("output") or "")
        if output and hasattr(self, "run_event_log"):
            self._append_event_log(output.rstrip())
        run_dir = Path(result.get("run_dir") or self._hypersafe_run_dir or "")
        status_path = run_dir / "state" / "hypersafe_bootstrap.txt"
        roots_path = run_dir / "state" / "hypersafe_root_folders.txt"
        state = self._read_state_file(status_path)
        returncode = int(result.get("returncode") or 0)
        status = str(state.get("status") or "")
        image_path = str(state.get("image_path") or run_dir / "source_image.img")
        map_path = str(state.get("map_path") or run_dir / "source_image.map")
        if (
            returncode == 0
            and status in {"ready", "ready_partial"}
            and Path(image_path).is_file()
            and Path(map_path).is_file()
            and roots_path.is_file()
        ):
            try:
                folders = [
                    line.strip("/\r\n")
                    for line in roots_path.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines()
                    if line.strip("/\r\n")
                ]
            except OSError as exc:
                folders = []
                output = f"{output}\nCould not read root-folder result: {exc}"
                returncode = -1
            if returncode == 0:
                self._selected_source["_interpreted_filesystem"] = "NTFS"
                self.source_panel.apply_hypersafe_preview(
                    folders,
                    image_path=image_path,
                    map_path=map_path,
                    status_path=str(status_path),
                )
                QMessageBox.information(
                    self,
                    "Hypersafe preview ready",
                    f"The sparse MFT preview is ready with {len(folders):,} root folder(s).\n\n"
                    "Expand only the branches you want to inspect.",
                )
                return

        if stop_requested or returncode == 130:
            self.source_panel._restore_source_meta()
            QMessageBox.information(
                self,
                "Hypersafe fetch stopped",
                "The metadata fetch was stopped. Its sparse image and ddrescue map "
                "have been kept; press Fetch MFT and show folder tree again with the same "
                "source and Service ID to resume.",
            )
            return

        self.source_panel._restore_source_meta()
        cleaned = ANSI_ESCAPE_RE.sub("", output)
        cleaned = TERMINAL_CONTROL_RE.sub("", cleaned)
        lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
        detail = str(state.get("detail") or "")
        tail = "\n".join(lines[-12:]) if lines else detail or "No output from carv."
        QMessageBox.warning(
            self,
            "Hypersafe folder fetch failed",
            "The sparse NTFS metadata preview was not completed. Its ddrescue image/map "
            "have been kept for a safe retry.\n\n" + tail,
        )

    def _set_live_monitor_status(self, detail: str = "") -> None:
        if not hasattr(self, "run_monitor_status"):
            return
        glyphs = ("◐", "◓", "◑", "◒")
        glyph = glyphs[self._run_busy_index % len(glyphs)]
        suffix = f" · {detail}" if detail else ""
        self.run_monitor_status.setText(
            f"LIVE MONITOR {glyph} {datetime.now().strftime('%H:%M:%S')}{suffix}"
        )

    def _advance_run_busy_indicator(self) -> None:
        process = self._process
        if process is None or process.poll() is not None:
            self._run_busy_timer.stop()
            return
        self._run_busy_index = (self._run_busy_index + 1) % 4
        self._run_activity_spinner_index = (self._run_activity_spinner_index + 1) % 4
        current_activity = ""
        if hasattr(self, "run_metric_values"):
            phase_label = self.run_metric_values.get("PHASE")
            current_activity = str(phase_label.text() or "") if phase_label is not None else ""
        detail = current_activity if current_activity and current_activity != "—" else "working"
        self._set_live_monitor_status(detail)
        self._refresh_run_activity_spinner()

    def _reset_run_monitor_for_start(self) -> None:
        self._evidence_cache = {"stamp": None, "data": None}
        self._tsv_rows_cache = {}
        self._last_evidence_refresh_at = 0.0
        self._hfs_evidence_refresh_pending = False
        self._hfs_legacy_recovery_cache = None
        self._modern_recovery_evidence_cache = None
        self._process_family_cache_at = 0.0
        self._process_family_cache = ({}, set(), set())
        self._resource_sample_at = 0.0
        self._activity_last_position = -1
        self._activity_last_signature = ""
        self._activity_last_progress_at = 0.0
        self._activity_last_problem_signature = ""
        self._activity_known_error_segments = []
        self._activity_known_skipped_segments = []
        self._activity_latest_output_count = -1
        self._activity_latest_output = ""
        self._run_progress_authority = ""
        self._hfs_progress_cache = {}
        self._last_hfs_progress_percent = 0.0
        self._last_run_display_percent = 0.0
        self._continue_image_requested = False
        self._ddrescue_continue_available = False
        self._ddrescue_image_only_run = False
        self._develop_time_buckets = {
            "source": 0.0,
            "validation": 0.0,
            "output_wait": 0.0,
            "metadata": 0.0,
            "restart_other": 0.0,
        }
        self._develop_time_last_sample_at = 0.0
        if hasattr(self, "run_develop_time_row"):
            self.run_develop_time_row.setText("DEVELOP TIME · waiting for samples")
        self.run_evidence_map.clear()
        self.run_evidence_summary.setText("No file findings yet")
        self.run_percent_value.setText("STARTING")
        self.run_preview_progress.setRange(0, 0)
        self.run_cursor_value.setText("Preparing filesystem work plan")
        self.run_eta_value.setText("ESTIMATING")
        self.run_elapsed_value.setText("Elapsed 00:00:00")
        self.run_cpu_value.setText("measuring")
        self.run_ram_value.setText("measuring")
        for value in self.run_metric_values.values():
            value.setText("—")
        self._run_activity_spinner_index = 0
        self._set_run_activity_body("", waiting_for_state=True)
        self.stop_button.setText("STOP RECOVERY")
        self.stop_button.setToolTip(
            "Request a clean stop. The button changes to KILL RECOVERY if the process does not exit."
        )
        self.stop_button.setStyleSheet(
            "QPushButton { color: #e6b6b6; border-color: #754747; background: #271b1d; "
            "font-weight: 700; letter-spacing: 0.8px; padding: 8px 16px; }"
            "QPushButton:hover { border-color: #b95c5c; background: #352124; }"
        )
        self.run_state_value.setText("●  RECOVERY ACTIVE")
        self.run_state_value.setStyleSheet(
            f"color: {ACCENT}; font-family: '{mono_font_family()}'; font-size: 10px; "
            "font-weight: 800; letter-spacing: 1px; border: none;"
        )
        self._set_live_monitor_status("starting")
        self._run_busy_index = 0
        self._reset_done_live_tree(
            self._current_run_dir / "recovered" if self._current_run_dir else None
        )
        self._run_busy_timer.start()

    def _start_recovery(self) -> None:
        if self._kernel_reboot_required:
            QMessageBox.critical(
                self,
                "Reboot required",
                "A ddrescue worker is still blocked inside the Linux kernel. Its "
                "image and map are saved, but another recovery must not start in "
                "this boot. Restart Ubuntu and then resume the same Service ID.",
            )
            return
        if self._process is not None and self._process.poll() is None:
            QMessageBox.information(self, "Already running", "A recovery process is already active.")
            return
        if self._source_test_thread is not None and self._source_test_thread.is_alive():
            QMessageBox.information(self, "JPEG test running", "Wait for the source JPEG test to finish first.")
            return
        self._refresh_plan_status()
        if not self.start_button.isEnabled():
            QMessageBox.warning(self, "Setup incomplete", self.plan_hint.text())
            return
        run_dir = self._run_directory()
        if run_dir is None:
            return
        policy = self._resolve_existing_run(run_dir)
        if policy is None:
            return
        try:
            run_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            QMessageBox.warning(self, "Output unavailable", f"Could not create the run folder:\n\n{exc}")
            return
        command_parts = shlex.split(self.command_preview.toPlainText())
        if any(part.startswith("<") and part.endswith(">") for part in command_parts):
            QMessageBox.warning(self, "Setup incomplete", "The command still contains unresolved values.")
            return
        self.source_panel.release_setup_sudo_for_recovery()
        execution_parts, execution_env, error = self._sudo_execution(command_parts)
        if error:
            QMessageBox.warning(self, "Start recovery", error)
            return
        execution_env = self._utf8_execution_environment(execution_env)
        self._remember_setup_preferences()
        self._current_run_dir = run_dir
        self._process_output = []
        self._run_command_parts = list(command_parts)
        self._live_metrics = {}
        self._run_ntfs_geometry = {}
        self._run_started_at = time.monotonic()
        self._run_started_wall_time = time.time()
        self._run_previous_elapsed_seconds = self._load_previous_run_elapsed(run_dir) if policy == "resume" else 0
        self._run_elapsed_recorded = False
        self._stop_requested = False
        self._recovery_known_pids = set()
        self._recovery_known_pgids = set()
        self._recovery_lingering_reported = False
        self._recovery_launcher_exit_seen_at = 0.0
        self._run_requested_make_image_first = (
            self.image_first_check.isChecked()
            or self._image_only_requested()
            or "--hypersafe-recover" in command_parts
            or "--hypersafe" in command_parts
        )
        self._reset_event_log()
        self._append_event_command(command_parts)
        if policy == "resume":
            self._append_gui_event("run_state_reused")
        elif policy == "restart":
            self._append_gui_event("previous_run_archived")
        try:
            self._process_started_with_sudo = bool(execution_parts) and execution_parts[0] == "sudo"
            resume_input = "y\ny\ny\ny\n" if policy == "resume" else ""
            self._process = subprocess.Popen(
                execution_parts,
                cwd=str(app_runtime_root()),
                env=execution_env,
                stdin=subprocess.PIPE if resume_input else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,
                bufsize=0,
                start_new_session=True,
            )
            self._recovery_known_pids = {self._process.pid}
            try:
                self._recovery_known_pgids = {os.getpgid(self._process.pid)}
            except OSError:
                self._recovery_known_pgids = set()
            if resume_input and self._process.stdin is not None:
                self._process.stdin.write(resume_input.encode("utf-8"))
                self._process.stdin.flush()
                self._process.stdin.close()
        except OSError as exc:
            self._process = None
            self._process_started_with_sudo = False
            QMessageBox.critical(self, "Launch failed", f"Could not start carv:\n\n{exc}")
            return
        self.source_panel.stop_folder_discovery_for_recovery()
        self._reset_run_monitor_for_start()
        self._process_reader_thread = threading.Thread(
            target=self._read_process_output,
            name="carv-process-output",
            daemon=True,
        )
        self._process_reader_thread.start()
        self.run_service_value.setText(self.service_id_combo.currentText().strip())
        image_only = self._image_only_requested()
        self._set_run_context_for_run(
            source_path=str(self._selected_source.get("path") or ""),
            destination_path=str(run_dir),
            mode_text=self.mode_combo.currentText(),
            image_only=image_only,
            hypersafe_immediate=self._hypersafe_immediate_requested(),
            hypersafe_priority=self._hypersafe_priority_recovery_requested(),
            hypersafe_tree=self._hypersafe_tree_recovery_requested(),
        )
        self.main_tabs.setCurrentIndex(1)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self._process_timer.start(1000)

    # ------------------------------------------------------------------
    # Run context presentation
    #
    # All field selection, ordering and operator-facing wording for the Run
    # context box lives here. Recovery setup supplies raw facts only.

    @staticmethod
    def _run_context_field_names() -> tuple[str, ...]:
        return ("Source", "Destination", "Mode", "Scope", "Filters")

    def _set_run_context_for_run(
        self,
        *,
        source_path: str,
        destination_path: str,
        mode_text: str,
        image_only: bool,
        hypersafe_immediate: bool,
        hypersafe_priority: bool,
        hypersafe_tree: bool,
    ) -> None:
        self._run_context_facts = {
            "source_path": str(source_path or ""),
            "destination_path": str(destination_path or ""),
            "mode_text": str(mode_text or ""),
            "image_only": bool(image_only),
            "hypersafe_immediate": bool(hypersafe_immediate),
            "hypersafe_priority": bool(hypersafe_priority),
            "hypersafe_tree": bool(hypersafe_tree),
        }
        self._render_run_context()

    def _set_run_context_destination(self, destination_path: str) -> None:
        self._run_context_facts["destination_path"] = str(
            destination_path or ""
        )
        self._render_run_context()

    def _render_run_context(self) -> None:
        if not hasattr(self, "run_context_values"):
            return
        facts = getattr(self, "_run_context_facts", {})
        if not facts:
            values = {name: "—" for name in self._run_context_field_names()}
        else:
            mode_text = str(facts.get("mode_text") or "")
            mode_key = mode_text.lower()
            image_only = bool(facts.get("image_only"))
            if bool(facts.get("hypersafe_immediate")):
                mode_display = "Image immediately · Hypersafe"
                scope_display = "Full source · Hypersafe image only"
            elif bool(facts.get("hypersafe_priority")):
                mode_display = (
                    "Folder Search · Hypersafe image only"
                    if image_only
                    else "Folder Search · Hypersafe"
                )
                scope_display = self._active_folder_scope_summary(
                    "No folders selected"
                )
            elif bool(facts.get("hypersafe_tree")):
                mode_display = (
                    "Tree Recovery · Hypersafe image only"
                    if image_only
                    else "Tree Recovery · Hypersafe"
                )
                scope_display = self._active_folder_scope_summary(
                    "No folders selected"
                )
            elif image_only:
                mode_display = "Image only · ddrescue"
                scope_display = "Full source · ddrescue image only"
            elif self._mode_text_is_raw_hunt(mode_key):
                mode_display = mode_text
                scope_display = "Full source · byte-sequential"
            elif "name" in mode_key:
                mode_display = mode_text
                scope_display = "Existing recovered output"
            else:
                mode_display = mode_text
                scope_display = self._active_folder_scope_summary(
                    "No folders selected"
                )
            values = {
                "Source": str(facts.get("source_path") or "—"),
                "Destination": str(facts.get("destination_path") or "—"),
                "Mode": mode_display or "—",
                "Scope": scope_display,
                "Filters": self._run_filter_summary(),
            }
        for field_name in self._run_context_field_names():
            self.run_context_values[field_name].setText(values[field_name])

    def _run_filter_summary(self) -> str:
        if self._image_only_requested():
            return "Not used in image-only mode"
        mode_text = self.mode_combo.currentText().lower()
        if "name" in mode_text:
            return "Not used in name mode"
        selected = self._selected_file_type_filter_labels()
        state = next((label for label, box in self.file_state_radios.items() if box.isChecked()), "All states")
        date_from = self.date_from_edit.text().strip()
        date_to = self.date_to_edit.text().strip()
        date_text = "all dates"
        if date_from:
            date_text = date_from if not date_to or date_to == date_from else f"{date_from}–{date_to}"
        parts = []
        if selected:
            parts.append(", ".join(selected))
        parts.extend((state, date_text))
        return " · ".join(parts)

    # End Run context presentation.

    @staticmethod
    def _sanitize_process_text(text: str) -> str:
        cleaned = ANSI_ESCAPE_RE.sub("", str(text or ""))
        return TERMINAL_CONTROL_RE.sub("", cleaned)

    @staticmethod
    def _state_path_text(text: str) -> str:
        cleaned = str(text or "").strip()
        return "" if "\x00" in cleaned else cleaned

    def _read_process_output(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        pending = ""
        ddrescue_progress_lines = []
        last_ddrescue_progress_flush = 0.0

        def queue_cleaned(cleaned: str, *, progress: bool = False) -> None:
            if not cleaned:
                return
            if progress:
                cleaned = DDRESCUE_PROGRESS_EVENT_PREFIX + cleaned
            with self._process_output_lock:
                self._process_output.append(cleaned)

        def flush_ddrescue_progress(force: bool = False) -> None:
            nonlocal ddrescue_progress_lines, last_ddrescue_progress_flush

            if not ddrescue_progress_lines:
                return
            now = time.monotonic()
            if not force and now - last_ddrescue_progress_flush < 3.0:
                return
            queue_cleaned("\n".join(ddrescue_progress_lines[-8:]), progress=True)
            ddrescue_progress_lines = []
            last_ddrescue_progress_flush = now

        def queue_line(raw_line: str) -> None:
            cleaned = self._sanitize_process_text(raw_line).rstrip()
            if not cleaned:
                return
            if DDRESCUE_PROGRESS_LINE_RE.search(cleaned):
                ddrescue_progress_lines.append(cleaned)
                flush_ddrescue_progress(force=False)
                return
            flush_ddrescue_progress(force=True)
            queue_cleaned(cleaned)

        try:
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                pending += chunk if isinstance(chunk, str) else decoder.decode(chunk)
                frames = re.split(r"\r\n|[\r\n]", pending)
                pending = frames.pop()
                for frame in frames:
                    queue_line(frame)
            if not isinstance(chunk, str):
                pending += decoder.decode(b"", final=True)
            queue_line(pending)
            flush_ddrescue_progress(force=True)
        except (OSError, ValueError):
            return

    # ------------------------------------------------------------------
    # Event log presentation
    #
    # Process reading above produces raw lines. Everything deciding which
    # lines the operator sees, how repetition is condensed and how ddrescue
    # progress is presented lives in this block.

    _EVENT_LOG_LEVEL_RE = re.compile(
        r"^\s*\[(ERROR|WARN|WARNING|FATAL)\]\s*",
        re.IGNORECASE,
    )
    _EVENT_LOG_IMPORTANT_RE = re.compile(
        r"("
        r"failed|failure|error|warning|warn|fatal|traceback|exception|permission denied|"
        r"read-only|disappeared|lost contact|retry budget exhausted|refusing|"
        r"stopped|kill|sigint|sigterm|sigkill|aborted|exited|completed|finished|"
        r"detected|loaded .*catalog|loaded .*overflow|configure timings|"
        r"phase \d+/\d+|image-first mode|image-only mode|ddrescue|recovery nap|"
        r"source image|filesystem target|folder path requested|metadata recovery|"
        r"photos library detected|recovery run ownership"
        r")",
        re.IGNORECASE,
    )
    _EVENT_LOG_NOISE_RE = re.compile(
        r"("
        r"^\s*$|"
        r"\b(?:pos|speed|eta|carved|named|unnamed|stalled|bg|note)=[^\\n]*$|"
        r"^\s*current operation\b|^\s*source position\b|^\s*last activity\b|"
        r"^\s*recovery\b|^\s*latest output\b|^\s*write pipeline\b"
        r")",
        re.IGNORECASE,
    )
    _EVENT_LOG_AGGREGATE_PATTERNS = (
        (
            re.compile(
                r"HFS\+\s+metadata recovery skipped incomplete data-fork runlist",
                re.IGNORECASE,
            ),
            "HFS+ skipped incomplete data-fork runlists; details remain in the backend logs",
        ),
        (
            re.compile(
                r"Failed to recover HFS\+\s+Catalog file",
                re.IGNORECASE,
            ),
            "HFS+ catalog-file recovery errors occurred; details remain in the backend logs",
        ),
        (
            re.compile(
                r"State monitor (?:cannot read|skipped a transient)",
                re.IGNORECASE,
            ),
            "GUI state monitor had transient state-read trouble; recovery continues",
        ),
    )

    def _reset_event_log(self, *, waiting: bool = False) -> None:
        self._event_log_lines = []
        self._event_log_progress_text = ""
        self._event_log_waiting = bool(waiting)
        self._run_event_suppressed = {}
        self._run_event_seen_signatures = set()
        self._run_event_signature_labels = {}
        self._render_event_log()

    @staticmethod
    def _operator_event_signature(line: str) -> str:
        compact = re.sub(r"\s+", " ", str(line or "").strip())
        compact = re.sub(r"/(?:[^/\s]+/){2,}[^:\s]+", "/…", compact)
        compact = re.sub(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?\b", "<time>", compact)
        compact = re.sub(r"\b\d+(?:\.\d+)?\s*(?:B|KiB|MiB|GiB|TiB|bytes?)\b", "<size>", compact, flags=re.IGNORECASE)
        compact = re.sub(r"\b\d+\b", "<n>", compact)
        return compact[:240]

    def _flush_suppressed_operator_events(self) -> list[str]:
        suppressed = getattr(self, "_run_event_suppressed", {})
        if not suppressed:
            return []
        labels = getattr(self, "_run_event_signature_labels", {})
        lines = []
        for signature, count in sorted(suppressed.items()):
            if count > 0:
                label = labels.get(signature, signature)
                lines.append(f"[GUI] Suppressed {count:,} repetitive event(s): {label}")
        self._run_event_suppressed = {}
        return lines

    def _operator_event_line(self, line: str) -> str | None:
        cleaned = self._sanitize_process_text(str(line or "")).replace("\r", " ").strip()
        if not cleaned:
            return None
        if cleaned.startswith("$ "):
            return cleaned

        normalized = re.sub(r"\s+", " ", cleaned)
        for pattern, label in self._EVENT_LOG_AGGREGATE_PATTERNS:
            if pattern.search(normalized):
                seen = getattr(self, "_run_event_seen_signatures", set())
                signature = f"aggregate:{label}"
                if signature in seen:
                    suppressed = getattr(self, "_run_event_suppressed", {})
                    suppressed[signature] = suppressed.get(signature, 0) + 1
                    self._run_event_suppressed = suppressed
                    return None
                seen.add(signature)
                self._run_event_seen_signatures = seen
                labels = getattr(self, "_run_event_signature_labels", {})
                labels[signature] = label
                self._run_event_signature_labels = labels
                return cleaned
        if cleaned.startswith("[GUI]"):
            return cleaned

        is_important = bool(
            self._EVENT_LOG_LEVEL_RE.search(normalized) or
            self._EVENT_LOG_IMPORTANT_RE.search(normalized)
        )
        if not is_important:
            return None
        if (
            self._EVENT_LOG_NOISE_RE.search(normalized)
            and not self._EVENT_LOG_LEVEL_RE.search(normalized)
        ):
            return None

        signature = self._operator_event_signature(normalized)
        seen = getattr(self, "_run_event_seen_signatures", set())
        if signature in seen:
            suppressed = getattr(self, "_run_event_suppressed", {})
            suppressed[signature] = suppressed.get(signature, 0) + 1
            self._run_event_suppressed = suppressed
            return None
        seen.add(signature)
        labels = getattr(self, "_run_event_signature_labels", {})
        labels[signature] = cleaned
        self._run_event_signature_labels = labels
        if len(seen) > 1500:
            seen = set(list(seen)[-1000:])
            self._run_event_signature_labels = {
                key: value for key, value in labels.items() if key in seen
            }
        self._run_event_seen_signatures = seen
        return cleaned

    def _append_event_command(self, command_parts: list[str]) -> None:
        self._append_event_log(
            "$ " + " ".join(shlex.quote(part) for part in command_parts)
        )

    def _append_gui_event(self, event: str, **facts) -> None:
        """Format GUI-authored Event log messages in one reviewable place."""
        if event == "run_state_reused":
            text = "[GUI] Reusing existing run state"
        elif event == "previous_run_archived":
            text = "[GUI] Previous run archived; starting clean"
        elif event == "elapsed_record_failed":
            text = f"[GUI] Could not record elapsed session: {facts.get('error')}"
        elif event == "read_problem":
            text = f"[WARN] Read problem zone: {facts.get('detail')}"
        elif event == "state_monitor_permission":
            text = (
                "[GUI] State monitor cannot read one or more run-state files yet "
                f"({facts.get('error')}); recovery continues."
            )
        elif event == "state_monitor_read_error":
            text = (
                "[GUI] State monitor skipped a transient state read error: "
                f"{facts.get('error')}"
            )
        elif event == "kernel_io_hang":
            text = (
                "[GUI ERROR] Linux kernel storage I/O has crashed. The ddrescue map is "
                "saved; this worker cannot be killed normally. Reboot Ubuntu before "
                "resuming the same Service ID."
            )
        elif event == "monitor_error":
            text = (
                "[GUI ERROR] Recovery monitor caught an internal error; "
                "the recovery output remains intact.\n"
                f"{facts.get('details')}"
            )
        elif event == "launcher_exited":
            text = (
                "[GUI] Launcher exited; waiting briefly for recovery workers "
                "to finish closing"
            )
        elif event == "recovery_workers_alive":
            pids = facts.get("pids") or []
            text = (
                "[GUI] The launcher exited but recovery descendants are still alive: "
                + ", ".join(str(pid) for pid in pids)
            )
        elif event == "process_exited":
            text = f"[GUI] carv exited with status {facts.get('return_code')}"
        elif event == "done_tree_permission":
            text = (
                "[GUI] Live Done tree cannot read run-state yet "
                f"({facts.get('error')}); recovery continues."
            )
        elif event == "done_tree_read_error":
            text = (
                "[GUI] Live Done tree skipped a transient state read error: "
                f"{facts.get('error')}"
            )
        elif event == "done_browser_error":
            text = (
                "[WARN] Could not prepare the Done output browser: "
                f"{facts.get('error')}"
            )
        elif event == "imaging_stop_requested":
            text = (
                "[GUI] Requested clean imaging stop; keeping the partial image and map"
                if bool(facts.get("image_only"))
                else "[GUI] Requested clean imaging stop; continuing file recovery from the partial image"
            )
        elif event == "clean_stop_requested":
            text = (
                "[GUI] Clean ddrescue stop requested; partial image and map are being preserved"
                if facts.get("kind") == "ddrescue"
                else "[GUI] Clean stop requested for all known recovery process groups"
            )
            text += (
                "; use KILL RECOVERY if processes remain blocked"
                if facts.get("survivors")
                else "; process tree is exiting"
            )
        elif event == "forced_kill":
            survivors = facts.get("survivors") or []
            text = "[GUI] Forced kill sent to all known recovery process groups"
            if survivors:
                text += "; still visible: " + ", ".join(
                    str(pid) for pid in survivors
                )
        else:
            raise ValueError(f"Unknown GUI Event log message: {event}")
        self._append_event_log(text)

    def _append_event_log(self, text: str) -> None:
        cleaned = self._sanitize_process_text(str(text)).replace("\r\n", "\n").replace("\r", "\n").rstrip()
        if not cleaned:
            return
        if not hasattr(self, "_event_log_lines"):
            self._event_log_lines = []
        event_lines = []
        for raw_line in cleaned.splitlines():
            event_line = self._operator_event_line(raw_line)
            if event_line:
                event_lines.extend(self._flush_suppressed_operator_events())
                event_lines.append(event_line)
        if not event_lines:
            return
        self._event_log_waiting = False
        self._event_log_lines.extend(event_lines)
        if len(self._event_log_lines) > 1200:
            self._event_log_lines = self._event_log_lines[-1200:]
        self._render_event_log()

    def _set_event_log_progress(self, text: str) -> None:
        cleaned = self._sanitize_process_text(str(text)).replace("\r\n", "\n").replace("\r", "\n").rstrip()
        self._event_log_progress_text = cleaned
        if cleaned:
            self._event_log_waiting = False
        self._render_event_log()

    def _render_event_log(self) -> None:
        if not hasattr(self, "run_event_log"):
            return
        parts = list(getattr(self, "_event_log_lines", []))
        progress = str(getattr(self, "_event_log_progress_text", "") or "").strip()
        if progress:
            parts.append("DDRESCUE PROGRESS")
            parts.extend(progress.splitlines())
        if not parts and bool(getattr(self, "_event_log_waiting", False)):
            parts.append("Waiting for process output.")
        rendered = "\n".join(part for part in parts if part is not None)
        if self.run_event_log.toPlainText() != rendered:
            self.run_event_log.setPlainText(rendered)
        bar = self.run_event_log.verticalScrollBar()
        bar.setValue(bar.maximum())

    # End Event log presentation.

    @staticmethod
    def _format_duration(seconds: float) -> str:
        total = max(0, int(seconds))
        hours, remainder = divmod(total, 3600)
        minutes, secs = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    @staticmethod
    def _load_previous_run_elapsed(run_dir: Path) -> int:
        state_dir = run_dir / "state"
        ledger_total = 0
        try:
            for raw_line in (state_dir / "gui_run_sessions.tsv").read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or line.startswith("started_unix\t"):
                    continue
                fields = line.split("\t")
                if len(fields) >= 3:
                    ledger_total += max(0, int(float(fields[2])))
        except (OSError, TypeError, ValueError):
            pass
        stage = CarvGuiWindow._read_state_file(state_dir / "raw_all_stage.txt")
        stage_total = 0
        for key in ("budget_elapsed_seconds", "elapsed_seconds"):
            try:
                stage_total = max(stage_total, max(0, int(float(stage.get(key, 0) or 0))))
            except (TypeError, ValueError):
                continue
        return max(ledger_total, stage_total)

    def _current_run_elapsed(self) -> int:
        session = max(0, int(time.monotonic() - self._run_started_at)) if self._run_started_at else 0
        return max(0, int(self._run_previous_elapsed_seconds or 0) + session)

    def _record_run_elapsed(self, return_code: int) -> None:
        if self._run_elapsed_recorded or self._current_run_dir is None or not self._run_started_at:
            return
        self._run_elapsed_recorded = True
        duration = max(0, int(round(time.monotonic() - self._run_started_at)))
        if duration <= 0:
            return
        path = self._current_run_dir / "state" / "gui_run_sessions.tsv"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            needs_header = not path.exists() or path.stat().st_size == 0
            with path.open("a", encoding="utf-8") as handle:
                if needs_header:
                    handle.write("started_unix\tfinished_unix\tduration_seconds\texit_code\n")
                handle.write(
                    f"{self._run_started_wall_time:.3f}\t{time.time():.3f}\t{duration}\t{return_code}\n"
                )
        except OSError as exc:
            self._append_gui_event("elapsed_record_failed", error=exc)

    @staticmethod
    def _format_bytes(value: int) -> str:
        return SourcePickerDialog._human_bytes(max(0, int(value)))

    @staticmethod
    def _parse_byte_text(text: str) -> int | None:
        value = str(text or "").strip().replace("_", "").replace(" ", "")
        if not value:
            return None
        if value.lower().startswith("0x"):
            try:
                parsed = int(value, 16)
            except ValueError:
                return None
            return parsed if parsed >= 0 else None
        match = re.fullmatch(r"(\d+(?:[.,]\d+)?)([kmgtp]?i?b?|bytes?)?", value, re.IGNORECASE)
        if not match:
            return None
        number_text, suffix = match.groups()
        try:
            number = float(number_text.replace(",", "."))
        except ValueError:
            return None
        suffix = (suffix or "b").lower()
        multipliers = {
            "": 1,
            "b": 1,
            "byte": 1,
            "bytes": 1,
            "k": 1000,
            "kb": 1000,
            "ki": 1024,
            "kib": 1024,
            "m": 1000 ** 2,
            "mb": 1000 ** 2,
            "mi": 1024 ** 2,
            "mib": 1024 ** 2,
            "g": 1000 ** 3,
            "gb": 1000 ** 3,
            "gi": 1024 ** 3,
            "gib": 1024 ** 3,
            "t": 1000 ** 4,
            "tb": 1000 ** 4,
            "ti": 1024 ** 4,
            "tib": 1024 ** 4,
            "p": 1000 ** 5,
            "pb": 1000 ** 5,
            "pi": 1024 ** 5,
            "pib": 1024 ** 5,
        }
        multiplier = multipliers.get(suffix)
        if multiplier is None:
            return None
        parsed = round(number * multiplier)
        return parsed if parsed >= 0 else None

    def _format_advanced_byte_value(self, value: int, *, zero_text: str) -> str:
        value = max(0, int(value or 0))
        return zero_text if value == 0 else f"{value:,} B · {self._format_bytes(value)}"

    @staticmethod
    def _merge_spans(spans):
        merged = []
        for start, end in sorted((max(0, int(a)), max(0, int(b))) for a, b in spans if int(b) > int(a)):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged

    def _read_tsv_rows(self, path: Path, fieldnames=None):
        cache = getattr(self, "_tsv_rows_cache", None)
        if cache is None:
            cache = {}
            self._tsv_rows_cache = cache
        key = (str(path), tuple(fieldnames or ()))
        try:
            stat = path.stat()
        except OSError:
            cache.pop(key, None)
            return []
        cached = cache.get(key)
        identity = (int(stat.st_dev), int(stat.st_ino))
        if (
            cached is not None
            and cached["identity"] == identity
            and cached["size"] == stat.st_size
            and cached["mtime_ns"] == stat.st_mtime_ns
        ):
            return cached["rows"]

        append_safe = path.name in {
            "gui_recovery_evidence.tsv",
            "gui_trouble_evidence.tsv",
        }
        if (
            append_safe
            and cached is not None
            and cached["identity"] == identity
            and cached["ends_with_newline"]
            and stat.st_size > cached["size"]
        ):
            try:
                with path.open("rb") as handle:
                    handle.seek(cached["size"])
                    appended = handle.read()
            except OSError:
                appended = b""
            if appended and appended.endswith((b"\n", b"\r")):
                lines = appended.decode("ascii", errors="replace").splitlines()
                lines = [
                    line for line in lines
                    if line.strip() and not line.lstrip().startswith("#")
                ]
                new_rows = list(csv.DictReader(
                    lines,
                    delimiter="\t",
                    fieldnames=cached["columns"],
                )) if lines else []
                rows = cached["rows"] + new_rows
                cache[key] = {
                    "identity": identity,
                    "size": stat.st_size,
                    "mtime_ns": stat.st_mtime_ns,
                    "ends_with_newline": True,
                    "columns": cached["columns"],
                    "rows": rows,
                }
                return rows

        try:
            payload = path.read_bytes()
        except OSError:
            cache.pop(key, None)
            return []
        lines = payload.decode("ascii", errors="replace").splitlines()
        lines = [line for line in lines if line.strip() and not line.lstrip().startswith("#")]
        if not lines:
            cache[key] = {
                "identity": identity,
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "ends_with_newline": payload.endswith((b"\n", b"\r")),
                "columns": tuple(fieldnames or ()),
                "rows": [],
            }
            return []
        first_field = lines[0].split("\t", 1)[0].strip()
        headerless = bool(re.fullmatch(r"\d+", first_field)) or (
            bool(fieldnames) and fieldnames[0] == "pass_id" and bool(re.fullmatch(r"p\d+", first_field.lower()))
        )
        if fieldnames and headerless:
            columns = tuple(fieldnames)
            rows = list(csv.DictReader(lines, delimiter="\t", fieldnames=columns))
        else:
            columns = tuple(lines[0].split("\t"))
            rows = list(csv.DictReader(lines, delimiter="\t"))
        cache[key] = {
            "identity": identity,
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "ends_with_newline": payload.endswith((b"\n", b"\r")),
            "columns": columns,
            "rows": rows,
        }
        return rows

    @staticmethod
    def _evidence_artifact(state_dir: Path, name: str) -> Path:
        state_candidate = state_dir / name
        run_candidate = state_dir.parent / name
        if (
            CarvGuiWindow._path_exists(state_candidate)
            or not CarvGuiWindow._path_exists(run_candidate)
        ):
            return state_candidate
        return run_candidate

    @staticmethod
    def _map_int(row: dict, *keys: str, default: int = 0) -> int:
        for key in keys:
            value = row.get(key)
            if value not in (None, ""):
                try:
                    return int(value)
                except (TypeError, ValueError):
                    continue
        return int(default)

    def _range_segment(
        self,
        row: dict,
        *,
        start_keys=("start_offset", "offset"),
        end_keys=("end_offset",),
        kind: str = "",
        source: str = "",
        confidence: str = "exact",
        label: str = "",
        count: int = 1,
    ) -> DiskMapSegment | None:
        start = max(0, self._map_int(row, *start_keys))
        end = max(start, self._map_int(row, *end_keys, default=start))
        if end <= start:
            byte_count = max(0, self._map_int(row, "bytes", "length"))
            end = start + byte_count
        if end <= start:
            return None
        return DiskMapSegment(
            start,
            end,
            "span",
            kind or str(row.get("kind") or ""),
            confidence,
            source,
            label,
            max(1, int(count or 1)),
        )

    @staticmethod
    def _dedupe_map_segments(segments):
        unique = []
        seen = set()
        for segment in segments:
            key = (
                int(segment.start_offset), int(segment.end_offset), segment.geometry,
                segment.kind, segment.confidence, segment.label,
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(segment)
        return sorted(unique, key=lambda item: (item.start_offset, item.end_offset, item.label))

    def _merge_map_segments(self, segments, *, kind: str, source: str, confidence: str = "exact"):
        merged = self._merge_spans(
            (segment.start_offset, segment.end_offset)
            for segment in segments
            if segment.end_offset > segment.start_offset
        )
        return [
            DiskMapSegment(start, end, "span", kind, confidence, source)
            for start, end in merged
        ]

    def _subtract_map_segments(self, segments, covered):
        cuts = self._merge_spans(
            (segment.start_offset, segment.end_offset)
            for segment in covered
            if segment.end_offset > segment.start_offset
        )
        if not cuts:
            return list(segments)
        remaining = []
        for segment in segments:
            pieces = [(segment.start_offset, segment.end_offset)]
            for cut_start, cut_end in cuts:
                next_pieces = []
                for start, end in pieces:
                    if cut_end <= start or cut_start >= end:
                        next_pieces.append((start, end))
                        continue
                    if cut_start > start:
                        next_pieces.append((start, min(end, cut_start)))
                    if cut_end < end:
                        next_pieces.append((max(start, cut_end), end))
                pieces = next_pieces
                if not pieces:
                    break
            for start, end in pieces:
                if end > start:
                    remaining.append(DiskMapSegment(
                        start, end, "span", segment.kind, segment.confidence,
                        segment.source, segment.label, segment.count,
                    ))
        return remaining

    @staticmethod
    def _clip_map_segments(segments, source_size: int):
        clipped = []
        rejected = 0
        for segment in segments:
            start = max(0, int(segment.start_offset))
            end = max(start, int(segment.end_offset))
            if source_size > 0:
                if start >= source_size:
                    rejected += 1
                    continue
                end = min(source_size, end)
            geometry = segment.geometry
            if geometry != "point" and end <= start:
                rejected += 1
                continue
            clipped.append(DiskMapSegment(
                start, end, geometry, segment.kind, segment.confidence,
                segment.source, segment.label, segment.count,
            ))
        return clipped, rejected

    @staticmethod
    def _clip_map_segments_to_view(segments, view_start: int, view_end: int):
        if view_end <= view_start:
            return list(segments)
        visible = []
        for segment in segments:
            start = int(segment.start_offset)
            end = int(segment.end_offset)
            if segment.geometry == "point" or end <= start:
                if view_start <= start <= view_end:
                    visible.append(segment)
                continue
            clipped_start = max(view_start, start)
            clipped_end = min(view_end, end)
            if clipped_end <= clipped_start:
                continue
            visible.append(DiskMapSegment(
                clipped_start,
                clipped_end,
                segment.geometry,
                segment.kind,
                segment.confidence,
                segment.source,
                segment.label,
                segment.count,
            ))
        return visible

    def _read_recovered_output_segments(self, state_dir: Path):
        path = self._evidence_artifact(state_dir, "recovered_outputs.tsv")
        segments = []
        output_paths = set()
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return segments, output_paths
        for line in lines:
            if not line or line.startswith("offset\t"):
                continue
            fields = line.split("\t")
            if len(fields) < 2:
                continue
            try:
                start = max(0, int(fields[0].strip()))
            except ValueError:
                continue
            path_text = self._state_path_text(fields[1])
            if path_text:
                output_paths.add(path_text)
            output_path = Path(path_text) if path_text else None
            label = output_path.name if output_path is not None else "Recovered output"
            segments.append(DiskMapSegment(
                start,
                start,
                "point",
                "recovered",
                "marker",
                "recovered_outputs.tsv",
                label,
            ))
        return self._dedupe_map_segments(segments), output_paths

    @staticmethod
    def _evidence_bucket_width(source_size: int, *, max_buckets: int = 4096) -> int:
        size = max(0, int(source_size or 0))
        if size <= 0:
            return 64 * 1024 * 1024
        return max(1, (size + max_buckets - 1) // max_buckets)

    def _read_modern_recovery_segments(
        self,
        state_dir: Path,
        source_size: int,
    ) -> tuple[list[DiskMapSegment], int]:
        """Incrementally aggregate live recovery evidence into display bins."""
        path = self._evidence_artifact(state_dir, "gui_recovery_evidence.tsv")
        stat = self._path_stat(path)
        if stat is None or stat.st_size <= 0:
            self._modern_recovery_evidence_cache = None
            return [], 0

        path_text = str(path)
        identity = (int(stat.st_dev), int(stat.st_ino))
        bucket_width = self._evidence_bucket_width(source_size)
        cached = self._modern_recovery_evidence_cache
        reusable = bool(
            cached is not None
            and cached.get("path") == path_text
            and cached.get("identity") == identity
            and cached.get("bucket_width") == bucket_width
            and int(cached.get("position", 0)) <= stat.st_size
        )
        if not reusable:
            cached = {
                "path": path_text,
                "identity": identity,
                "bucket_width": bucket_width,
                "position": 0,
                "bins": {},
                "output_count": 0,
            }

        bins = cached["bins"]
        position = max(0, int(cached.get("position", 0)))
        try:
            with path.open("rb") as handle:
                handle.seek(position)
                while True:
                    line_start = handle.tell()
                    raw = handle.readline(1024 * 1024)
                    if not raw:
                        break
                    if not raw.endswith(b"\n"):
                        handle.seek(line_start)
                        break
                    line = raw.decode("ascii", errors="replace").strip()
                    if not line or line.lower().startswith("pass_id\t"):
                        continue
                    fields = line.split("\t")
                    if len(fields) < 7:
                        continue
                    try:
                        start = max(0, int(fields[2] or 0))
                        end = max(start, int(fields[3] or start))
                        count = max(1, int(fields[6] or 1))
                    except ValueError:
                        continue
                    geometry = "point" if fields[1].strip().lower() == "point" else "span"
                    kind = fields[4].strip() or "recovered"
                    confidence = fields[5].strip() or "marker"
                    if confidence != "exact" or end <= start:
                        geometry = "point"
                        end = start
                    bucket = start // bucket_width
                    key = (bucket, geometry)
                    current = bins.get(key)
                    if current is None:
                        bins[key] = [start, end, count, kind, confidence]
                    else:
                        current[0] = min(current[0], start)
                        current[1] = max(current[1], end)
                        current[2] += count
                        if current[3] != kind:
                            current[3] = "recovered"
                        if current[4] != confidence:
                            current[4] = "mixed"
                    cached["output_count"] += count
                cached["position"] = handle.tell()
        except OSError:
            return [], 0

        self._modern_recovery_evidence_cache = cached
        segments = [
            DiskMapSegment(
                values[0],
                values[1],
                key[1],
                values[3],
                values[4],
                "gui_recovery_evidence.tsv (display-binned)",
                "",
                values[2],
            )
            for key, values in bins.items()
        ]
        return segments, max(0, int(cached.get("output_count", 0)))

    def _read_hfs_legacy_recovery_once(self, state_dir: Path, source_size: int):
        """Load pre-existing HFS+ output positions once, without statting files."""
        path = self._evidence_artifact(state_dir, "recovered_outputs.tsv")
        bucket_width = self._evidence_bucket_width(source_size)
        cache_key = f"{path}:{bucket_width}"
        cached = self._hfs_legacy_recovery_cache
        if cached is not None and cached[0] == cache_key:
            return list(cached[1]), int(cached[2])

        by_bucket = {}
        output_count = 0
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if not line or line.startswith("offset\t"):
                        continue
                    fields = line.rstrip("\r\n").split("\t", 2)
                    if len(fields) < 2:
                        continue
                    try:
                        offset = max(0, int(fields[0].strip()))
                    except ValueError:
                        continue
                    output_count += 1
                    bucket = offset // bucket_width
                    current = by_bucket.get(bucket)
                    if current is None:
                        by_bucket[bucket] = [offset, 1]
                    else:
                        current[0] = min(current[0], offset)
                        current[1] += 1
        except OSError:
            pass

        segments = [
            DiskMapSegment(
                offset,
                offset,
                "point",
                "legacy recovered output",
                "marker",
                "recovered_outputs.tsv",
                "",
                count,
            )
            for offset, count in by_bucket.values()
        ]
        self._hfs_legacy_recovery_cache = (cache_key, tuple(segments), output_count)
        return segments, output_count

    def _runtime_ntfs_geometry(self, state_dir: Path) -> dict:
        if self._run_ntfs_geometry.get("cluster_size"):
            return dict(self._run_ntfs_geometry)
        path = self._evidence_artifact(state_dir, "runtime_events.log")
        pattern = re.compile(
            r"NTFS geometry:\s*preferred_volume_offset=(\d+)\s+cluster_size=(\d+)",
            re.IGNORECASE,
        )
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    match = pattern.search(line)
                    if match:
                        self._run_ntfs_geometry = {
                            "preferred_volume_offset": int(match.group(1)),
                            "cluster_size": int(match.group(2)),
                        }
        except OSError:
            pass
        return dict(self._run_ntfs_geometry)

    def _build_disk_map_snapshot(
        self,
        state_dir: Path,
        *,
        source_size: int,
        scan_offset: int,
        scan_mode: str,
    ) -> DiskMapSnapshot:
        snapshot = DiskMapSnapshot(source_size=max(0, int(source_size or 0)))
        activity = self._read_state_file(
            self._evidence_artifact(state_dir, "thread_activity.txt")
        )
        stage = self._read_state_file(
            self._evidence_artifact(state_dir, "raw_all_stage.txt")
        )

        def state_file_is_current(name: str) -> bool:
            stat = self._path_stat(self._evidence_artifact(state_dir, name))
            return bool(
                stat is not None
                and (
                    not self._run_started_wall_time
                    or stat.st_mtime >= self._run_started_wall_time - 1.0
                )
            )

        stage_current = state_file_is_current("raw_all_stage.txt")
        activity_current = state_file_is_current("thread_activity.txt")
        command_source_size = max(
            snapshot.source_size,
            max(0, self._map_int(stage, "source_size_bytes")),
            max(0, self._map_int(activity, "scan.source_size")),
        )
        command_scope = self._active_run_scope_from_command(command_source_size)
        if command_scope is not None:
            snapshot.source_size = max(snapshot.source_size, command_scope[2])
        current_scope = command_scope[:2] if command_scope is not None else None
        if stage_current:
            stage_source_size = max(0, self._map_int(stage, "source_size_bytes"))
            if stage_source_size > 0:
                snapshot.source_size = max(snapshot.source_size, stage_source_size)
            stage_start = max(0, self._map_int(stage, "selected_scope_start_bytes"))
            stage_end = max(stage_start, self._map_int(stage, "selected_scope_end_bytes"))
            if current_scope is None and stage_end > stage_start:
                current_scope = (stage_start, stage_end)
        if current_scope is None and activity_current:
            activity_source_size = max(0, self._map_int(activity, "scan.source_size"))
            if activity_source_size > 0:
                snapshot.source_size = max(snapshot.source_size, activity_source_size)
            activity_total = max(0, self._map_int(activity, "scan.total_bytes"))
            activity_progress = max(0, self._map_int(activity, "scan.progress_bytes"))
            activity_offset = max(0, self._map_int(activity, "scan.offset"))
            if activity_total > 0:
                inferred_start = max(0, activity_offset - activity_progress)
                inferred_end = inferred_start + activity_total
                if snapshot.source_size > 0:
                    inferred_end = min(snapshot.source_size, inferred_end)
                if inferred_end > inferred_start:
                    current_scope = (inferred_start, inferred_end)

        # Retry workers expose a small per-chunk denominator (normally
        # 64 MiB).  That is useful for their own status, but cumulative
        # evidence must never zoom to that chunk and make all earlier file
        # findings/errors appear to vanish.  Keep the operator-selected scope,
        # or the complete source when the original command is unavailable.
        map_stage_name = str(stage.get("stage") or "").strip().lower()
        if map_stage_name in {
            "retry_hotspots", "coverage_gap_retry", "post_scan_reconcile",
            "recover_missed", "post_scan_finalize", "auto_name_handoff",
        }:
            if command_scope is not None:
                current_scope = command_scope[:2]
            elif snapshot.source_size > 0:
                current_scope = (0, snapshot.source_size)
            snapshot.notes.append(
                "Post-scan retry is shown over the full recovery scope; cumulative findings are retained."
            )

        pass_rows = self._read_tsv_rows(
            self._evidence_artifact(state_dir, "gui_passes.tsv"),
            (
                "pass_id", "pass_index", "mode", "kind", "label", "range_kind",
                "range_start_offset", "range_end_offset", "source_size",
                "started_unix", "ended_unix", "status",
            ),
        )
        selected_view = None
        for row in pass_rows:
            pass_size = max(0, self._map_int(row, "source_size"))
            snapshot.source_size = max(snapshot.source_size, pass_size)
            start = max(0, self._map_int(row, "range_start_offset"))
            end = max(start, self._map_int(row, "range_end_offset", default=pass_size))
            if end > start:
                status = str(row.get("status") or "").strip().lower()
                range_kind = str(row.get("range_kind") or "").strip().lower()
                pass_index = max(0, self._map_int(row, "pass_index"))
                priority = (
                    2 if status == "running" else
                    1 if range_kind == "selected_range" else 0,
                    pass_index,
                )
                if priority[0] > 0 and (selected_view is None or priority > selected_view[0]):
                    selected_view = (priority, start, end)
                snapshot.scope.append(DiskMapSegment(
                    start, end, "span", str(row.get("kind") or "pass"),
                    "scope", "gui_passes.tsv", str(row.get("label") or ""),
                ))
        if current_scope is not None:
            snapshot.view_start_offset = current_scope[0]
            snapshot.view_end_offset = current_scope[1]
        elif selected_view is not None:
            snapshot.view_start_offset = selected_view[1]
            snapshot.view_end_offset = selected_view[2]

        if snapshot.view_end_offset <= snapshot.view_start_offset:
            activity_total = max(0, self._map_int(activity, "scan.total_bytes"))
            activity_progress = max(0, self._map_int(activity, "scan.progress_bytes"))
            activity_offset = max(0, self._map_int(activity, "scan.offset"))
            if activity_total > 0 and snapshot.source_size > activity_total:
                inferred_start = max(0, activity_offset - activity_progress)
                inferred_end = min(snapshot.source_size, inferred_start + activity_total)
                if inferred_end > inferred_start:
                    snapshot.view_start_offset = inferred_start
                    snapshot.view_end_offset = inferred_end
        normalized_mode = str(scan_mode or activity.get("mode") or "").strip().lower()
        coverage_rows = self._read_tsv_rows(
            self._evidence_artifact(state_dir, "gui_read_coverage.tsv"),
            ("pass_id", "start_offset", "end_offset"),
        )
        for row in coverage_rows:
            segment = self._range_segment(row, kind="read", source="gui_read_coverage.tsv")
            if segment:
                snapshot.read.append(segment)
        read_source = "gui_read_coverage.tsv" if snapshot.read else ""
        read_confidence = "exact" if snapshot.read else ""
        if not snapshot.read and normalized_mode == "all" and scan_offset > 0:
            end = min(scan_offset, snapshot.source_size) if snapshot.source_size > 0 else scan_offset
            if end > 0:
                snapshot.read.append(DiskMapSegment(
                    0, end, "span", "sequential progress", "estimated", "scan_offset",
                ))
                read_source = "scan_offset"
                read_confidence = "estimated"
                snapshot.notes.append("Read coverage is estimated from the sequential scan cursor.")
        if not snapshot.read and normalized_mode in {"folders", "folder", "filesystem"}:
            prefix_bytes = max(0, self._map_int(
                activity,
                "prefix.bytes_processed",
                "metadata.bytes_processed",
                "bytes_processed",
            ))
            end = min(prefix_bytes, snapshot.source_size) if snapshot.source_size > 0 else prefix_bytes
            if end > 0:
                snapshot.read.append(DiskMapSegment(
                    0,
                    end,
                    "span",
                    "filesystem metadata scan",
                    "measured",
                    "thread_activity.txt:prefix.bytes_processed",
                ))
                read_source = "thread_activity.txt"
                read_confidence = "measured"
                snapshot.notes.append(
                    "Tree recovery read coverage comes from the backend's measured prefix byte counter."
                )

        modern_recovery, modern_output_count = (
            self._read_modern_recovery_segments(state_dir, snapshot.source_size)
        )

        # Modern recovery evidence already carries source positions and output
        # counts.  Re-reading recovered_outputs.tsv here is both redundant and
        # very expensive for large metadata recoveries: the legacy reader also
        # stats every recovered path.  Keep that fallback only for older runs
        # which do not emit gui_recovery_evidence.tsv.
        saved_hfs_state = self._read_state_file(
            state_dir / "hfsplus_recovery_progress.txt"
        )
        hfs_evidence_active = (
            self._run_progress_authority == "hfsplus"
            or str(saved_hfs_state.get("backend") or "").strip().lower() == "hfsplus"
        )
        hfs_legacy_recovery = []
        hfs_legacy_output_count = 0
        if hfs_evidence_active:
            output_recovery, output_paths = [], set()
            hfs_legacy_recovery, hfs_legacy_output_count = (
                self._read_hfs_legacy_recovery_once(
                    state_dir,
                    snapshot.source_size,
                )
            )
        else:
            output_recovery, output_paths = self._read_recovered_output_segments(state_dir)
        mft_recovery, mft_positioned_paths, mft_output_paths, mft_notes = self._load_folders_recovered_segments(state_dir)
        snapshot.notes.extend(mft_notes)
        if hfs_evidence_active:
            # Resume is cumulative: retain positions from older output logs and
            # union them with every modern extent recorded by later passes.
            snapshot.recovered = self._dedupe_map_segments(
                modern_recovery + hfs_legacy_recovery + mft_recovery
            )
        elif modern_recovery:
            snapshot.recovered = modern_recovery
            # Exact MFT extents can replace marker-only modern evidence.
            if mft_recovery and not any(item.confidence == "exact" for item in modern_recovery):
                snapshot.recovered = mft_recovery
        elif mft_recovery:
            snapshot.recovered = mft_recovery
        else:
            snapshot.recovered = output_recovery
        snapshot.recovered_outputs = max(
            len(output_paths),
            modern_output_count,
            len(mft_output_paths),
            hfs_legacy_output_count,
        )
        snapshot.positioned_outputs = max(
            len(mft_positioned_paths),
            len(output_paths) if output_recovery else 0,
            modern_output_count if modern_recovery else 0,
            hfs_legacy_output_count,
        )
        snapshot.recovered_count_is_files = bool(
            output_paths
            or mft_output_paths
            or (hfs_evidence_active and (modern_output_count or hfs_legacy_output_count))
        )

        # A recovered span was necessarily read even when an older/sparse
        # backend did not emit gui_read_coverage.tsv for that pass.
        recovered_read_spans = [
            DiskMapSegment(
                item.start_offset,
                item.end_offset,
                "span",
                "recovered file read",
                "inferred",
                item.source or "recovery evidence",
                item.label,
                item.count,
            )
            for item in snapshot.recovered
            if item.geometry != "point" and item.end_offset > item.start_offset
        ]
        if recovered_read_spans:
            snapshot.read.extend(recovered_read_spans)
            if not read_source:
                read_source = "recovery evidence"
                read_confidence = "inferred"
                snapshot.notes.append(
                    "Read coverage includes recovered extents inferred from successful output reads."
                )
        snapshot.read = self._merge_map_segments(
            snapshot.read,
            kind="bytes read",
            source=read_source or "read evidence",
            confidence=read_confidence or "inferred",
        )

        gui_errors = []
        gui_skipped = []
        skip_kinds = {"deferred", "forced_skip", "skipped", "coverage_gap", "unread"}
        for row in self._read_tsv_rows(
            self._evidence_artifact(state_dir, "gui_trouble_evidence.tsv"),
            ("pass_id", "start_offset", "end_offset", "kind", "hit_count", "first_seen_unix", "last_seen_unix"),
        ):
            kind = str(row.get("kind") or "read_fail").strip().lower()
            segment = self._range_segment(
                row, kind=kind, source="gui_trouble_evidence.tsv",
                count=max(1, self._map_int(row, "hit_count", default=1)),
            )
            if segment:
                (gui_skipped if kind in skip_kinds else gui_errors).append(segment)

        compact_errors = []
        for row in self._read_tsv_rows(
            self._evidence_artifact(state_dir, "read_trouble_map.tsv"),
            ("offset", "end_offset", "bytes", "errno_code", "hit_count", "first_seen_unix", "last_seen_unix"),
        ):
            segment = self._range_segment(
                row, kind="read failure", source="read_trouble_map.tsv",
                count=max(1, self._map_int(row, "hit_count", default=1)),
            )
            if segment:
                compact_errors.append(segment)
        if not compact_errors:
            for row in self._read_tsv_rows(
                self._evidence_artifact(state_dir, "read_errors.tsv"),
                ("offset", "end_offset", "bytes", "errno_code", "granularity_bytes", "source_path", "run_id", "note"),
            ):
                segment = self._range_segment(row, kind="read failure", source="read_errors.tsv")
                if segment:
                    compact_errors.append(segment)

        deferred = []
        for row in self._read_tsv_rows(
            self._evidence_artifact(state_dir, "deferred_bad_zones.tsv"),
            ("offset", "end_offset", "bytes", "ranges"),
        ):
            segment = self._range_segment(
                row, kind="deferred read", source="deferred_bad_zones.tsv",
                count=max(1, self._map_int(row, "ranges", default=1)),
            )
            if segment:
                deferred.append(segment)

        coverage_gaps = []
        for row in self._read_tsv_rows(self._evidence_artifact(state_dir, "coverage_gaps.tsv")):
            status = str(row.get("status") or "").strip().lower()
            snapshot.source_size = max(snapshot.source_size, self._map_int(row, "source_size"))
            if status in {"coverage_unavailable", "no_large_gaps"}:
                continue
            segment = self._range_segment(
                row, start_keys=("start_offset",), end_keys=("end_offset",),
                kind=status or "coverage gap", source="coverage_gaps.tsv",
            )
            if segment:
                coverage_gaps.append(segment)
        if not coverage_gaps:
            for row in self._read_tsv_rows(self._evidence_artifact(state_dir, "coverage_gap_observations.tsv")):
                segment = self._range_segment(
                    row, start_keys=("gap_start",), end_keys=("gap_end",),
                    kind=str(row.get("status") or "coverage gap"),
                    source="coverage_gap_observations.tsv",
                )
                if segment:
                    coverage_gaps.append(segment)

        image_errors = []
        image_skipped = []
        for row in self._read_tsv_rows(
            self._evidence_artifact(state_dir, "source_image_bad_ranges.tsv"),
            ("offset", "end_offset", "bytes", "status", "kind"),
        ):
            kind = str(row.get("kind") or row.get("status") or "unresolved image range").strip().lower()
            segment = self._range_segment(row, kind=kind, source="source_image_bad_ranges.tsv")
            if segment:
                (
                    image_errors
                    if kind in {"bad_sector", "read_fail", "read_error"}
                    else image_skipped
                ).append(segment)

        last_bad = self._read_state_file(self._evidence_artifact(state_dir, "last_bad_read.txt"))
        last_bad_segment = self._range_segment(last_bad, kind="last bad read", source="last_bad_read.txt")
        if last_bad_segment:
            compact_errors.append(last_bad_segment)

        hfs_source_errors = []
        if hfs_evidence_active:
            for row in self._read_tsv_rows(
                self._evidence_artifact(state_dir, "hfsplus_recovery_failures.tsv")
            ):
                reason = str(row.get("reason") or "").strip().lower()
                if not reason.startswith("source_read_"):
                    continue
                start = max(0, self._map_int(row, "source_offset"))
                requested = max(0, self._map_int(row, "requested_bytes"))
                if requested <= 0:
                    continue
                hfs_source_errors.append(DiskMapSegment(
                    start,
                    start + requested,
                    "span",
                    reason,
                    "estimated",
                    "hfsplus_recovery_failures.tsv",
                    str(row.get("catalog_path") or ""),
                ))

        snapshot.errors = self._dedupe_map_segments(
            gui_errors + compact_errors + image_errors + hfs_source_errors
        )
        exact_read = [segment for segment in snapshot.read if segment.confidence == "exact"]
        snapshot.skipped = self._subtract_map_segments(
            self._dedupe_map_segments(gui_skipped + deferred + coverage_gaps + image_skipped),
            exact_read,
        )
        if read_confidence in {"measured", "estimated"}:
            # Progress/prefix counters describe how far processing advanced;
            # failed or forcibly skipped spans inside that cursor were not
            # successfully read and must remain holes in the blue layer.
            snapshot.read = self._subtract_map_segments(
                snapshot.read,
                snapshot.errors + snapshot.skipped,
            )

        observed_max = max(
            [snapshot.source_size, scan_offset]
            + [
                max(segment.start_offset, segment.end_offset)
                for bucket in (snapshot.scope, snapshot.read, snapshot.recovered, snapshot.errors, snapshot.skipped)
                for segment in bucket
            ]
        )
        if snapshot.source_size <= 0:
            snapshot.source_size = observed_max
        rejected_total = 0
        for bucket_name in ("scope", "read", "recovered", "errors", "skipped"):
            clipped, rejected = self._clip_map_segments(getattr(snapshot, bucket_name), snapshot.source_size)
            setattr(snapshot, bucket_name, clipped)
            rejected_total += rejected
        if snapshot.view_end_offset > snapshot.view_start_offset:
            for bucket_name in ("read", "recovered", "errors", "skipped"):
                setattr(
                    snapshot,
                    bucket_name,
                    self._clip_map_segments_to_view(
                        getattr(snapshot, bucket_name),
                        snapshot.view_start_offset,
                        snapshot.view_end_offset,
                    ),
                )
            snapshot.notes.append(
                "File findings percentages use the active selected byte range; "
                "tooltips retain absolute source offsets."
            )
        if rejected_total:
            snapshot.notes.append(
                f"Ignored {rejected_total:,} file finding(s) outside the known source coordinate space."
            )
        return snapshot

    def _disk_map_summary(self, snapshot: DiskMapSnapshot) -> str:
        read_union = self._merge_spans((item.start_offset, item.end_offset) for item in snapshot.read)
        error_union = self._merge_spans((item.start_offset, item.end_offset) for item in snapshot.errors)
        skipped_union = self._merge_spans((item.start_offset, item.end_offset) for item in snapshot.skipped)
        read_bytes = sum(end - start for start, end in read_union)
        error_bytes = sum(end - start for start, end in error_union)
        skipped_bytes = sum(end - start for start, end in skipped_union)
        if snapshot.recovered_outputs:
            count_label = "Files mapped" if snapshot.recovered_count_is_files else "File findings mapped"
            recovered_text = f"{count_label} {snapshot.positioned_outputs:,}/{snapshot.recovered_outputs:,}"
        else:
            recovered_text = f"Recovered {len(snapshot.recovered):,}"
        read_text = f"Read {self._format_bytes(read_bytes)}" if read_union else "Read map unavailable"
        scope_text = ""
        if snapshot.view_end_offset > snapshot.view_start_offset:
            scope_bytes = snapshot.view_end_offset - snapshot.view_start_offset
            scope_text = f"Scope {self._format_bytes(scope_bytes)}  ·  "
        return (
            f"{scope_text}{read_text}  ·  {recovered_text}  ·  "
            f"Errors {len(error_union):,} / {self._format_bytes(error_bytes)}  ·  "
            f"Skipped {len(skipped_union):,} / {self._format_bytes(skipped_bytes)}"
        )

    def _latest_problem_segment(self, snapshot: DiskMapSnapshot) -> tuple[DiskMapSegment | None, str]:
        candidates = [
            (segment, "read error")
            for segment in getattr(snapshot, "errors", []) or []
        ]
        candidates.extend(
            (segment, "skipped range")
            for segment in getattr(snapshot, "skipped", []) or []
        )
        if not candidates:
            return None, ""
        return max(
            candidates,
            key=lambda item: (
                int(item[0].start_offset),
                int(item[0].end_offset),
                1 if item[1] == "read error" else 0,
            ),
        )

    def _problem_segment_text(
        self,
        segment: DiskMapSegment,
        problem_label: str,
        *,
        error_zones: int,
        error_bytes: int,
        skipped_zones: int,
        skipped_bytes: int,
    ) -> str:
        start = max(0, int(segment.start_offset))
        end = max(start, int(segment.end_offset))
        length = max(0, end - start)
        details = [
            f"{problem_label} at {start:,}",
            f"0x{start:x}",
        ]
        if length > 0:
            details.append(f"length {self._format_bytes(length)}")
            details.append(f"ends {end:,} / 0x{end:x}")
        if segment.kind:
            details.append(str(segment.kind))
        if segment.source:
            details.append(str(segment.source))
        if segment.count and segment.count > 1:
            details.append(f"{segment.count:,} hit(s)")
        totals = []
        if error_zones:
            totals.append(f"errors {error_zones:,} zones / {self._format_bytes(error_bytes)}")
        if skipped_zones:
            totals.append(f"skipped {skipped_zones:,} ranges / {self._format_bytes(skipped_bytes)}")
        if totals:
            details.append("; ".join(totals))
        if segment.label:
            label = str(segment.label)
            if len(label) > 90:
                label = label[:87].rstrip() + "…"
            details.append(label)
        return " · ".join(details)

    @staticmethod
    def _last_nonempty_line(path: Path) -> str:
        try:
            with path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - 65536), os.SEEK_SET)
                lines = handle.read().decode("utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        return next((line.strip() for line in reversed(lines) if line.strip()), "")

    def _latest_recovered_output(self, state_dir: Path, recovered_count: int) -> str:
        line = self._last_nonempty_line(
            self._evidence_artifact(state_dir, "recovered_outputs.tsv")
        )
        if line and not line.lower().startswith("offset\t"):
            fields = line.split("\t")
            if len(fields) >= 2 and fields[1].strip():
                path_text = self._state_path_text(fields[1])
                if path_text:
                    output = Path(path_text)
                    try:
                        return str(output.relative_to(state_dir.parent))
                    except ValueError:
                        return output.name or str(output)

        # Never discover the newest output by walking the recovered tree from
        # Qt's event thread. Large output trees, particularly on exFAT, can
        # block in the kernel long enough to make STOP/KILL and the whole GUI
        # appear dead. Backends should publish recovered_outputs.tsv; without
        # it we retain the last safe value instead of probing the destination.
        if recovered_count == self._activity_latest_output_count:
            return self._activity_latest_output
        self._activity_latest_output_count = recovered_count
        return self._activity_latest_output

    # ------------------------------------------------------------------
    # Activity presentation
    #
    # This is the single GUI-owned presentation block for the Activity box.
    # State readers below this block pass facts (counts, statuses and backend
    # detail) only; headings, fallbacks and operator-facing summaries belong
    # here so wording can be reviewed without tracing the state machinery.

    def _set_run_activity_body(
        self,
        body: str,
        *,
        waiting_for_state: bool = False,
    ) -> None:
        if body:
            self._run_activity_body = str(body)
        elif waiting_for_state:
            self._run_activity_body = "Waiting for activity state."
        else:
            self._run_activity_body = "Waiting for run activity."
        self._refresh_run_activity_spinner()

    def _refresh_run_activity_spinner(self) -> None:
        if not hasattr(self, "run_activity_text"):
            return
        process = self._process
        if process is not None and process.poll() is None:
            spinner = "|/-\\"[self._run_activity_spinner_index % 4]
            heartbeat = (
                "ACTIVITY HEARTBEAT\n"
                f"{spinner} process alive · {datetime.now().strftime('%H:%M:%S')}"
            )
            text = f"{heartbeat}\n\n{self._run_activity_body}"
        else:
            text = self._run_activity_body
        self.run_activity_text.setPlainText(text)

    def _activity_hypersafe_presentation(self, facts: dict) -> dict:
        """Turn raw Hypersafe state into Activity-only operator text."""
        hypersafe = facts.get("state")
        if not isinstance(hypersafe, dict):
            hypersafe = {}

        source_status = str(facts.get("source_status") or "").strip().lower()
        source_condition = {
            "identity_mismatch": "Wrong source rejected; no imaging resumed",
            "identity_unavailable": (
                "Source present; waiting until identity evidence can be read"
            ),
            "waiting_for_source": (
                "Selected source is unavailable; mapfile is preserved"
            ),
            "verifying_source": "Checking returning source identity",
        }.get(source_status, "Bound source connected")

        presentation = {
            "position_heading": "IMAGE COVERAGE",
            "source_condition": source_condition,
            "latest_event": str(facts.get("detail") or "").strip(),
            "priority_sections": [],
        }
        if not bool(facts.get("selected")):
            return presentation

        selected_files = max(0, self._map_int(hypersafe, "selected_files"))
        selected_ranges = max(
            0, self._map_int(hypersafe, "selected_domain_ranges")
        )
        selected_bytes = max(
            0, self._map_int(hypersafe, "selected_domain_bytes")
        )
        selected_imaged_ranges = max(
            0, self._map_int(hypersafe, "selected_domain_imaged_ranges")
        )
        selected_partial_ranges = max(
            0, self._map_int(hypersafe, "selected_domain_partial_ranges")
        )
        selected_unread_ranges = max(
            0, self._map_int(hypersafe, "selected_domain_unread_ranges")
        )
        selected_imaged_bytes = max(
            0, self._map_int(hypersafe, "selected_domain_imaged_bytes")
        )
        selected_unresolved_bytes = max(
            0, self._map_int(hypersafe, "selected_domain_unresolved_bytes")
        )
        query_count = max(0, int(facts.get("query_count") or 0))
        matched_count = max(0, int(facts.get("matched_count") or 0))
        folder_resolution_ready = bool(facts.get("folder_resolution_ready"))
        priority_plan_status = str(
            hypersafe.get("priority_plan_status") or ""
        ).strip().lower()
        priority_plan_detail = str(
            hypersafe.get("priority_plan_detail") or ""
        ).strip()
        priority_plan_unavailable = priority_plan_status == "unavailable"

        if priority_plan_unavailable:
            priority_plan = (
                f"{priority_plan_detail or 'Requested folder priority could not be built'} · "
                "full-source imaging continues"
            )
        else:
            folder_match_text = (
                f"{matched_count:,} unique matching MFT folder(s)"
                if folder_resolution_ready
                else "matching MFT folder count pending"
            )
            priority_plan = (
                f"{query_count:,} search term(s) · {folder_match_text} · "
                f"{selected_files:,} selected file record(s) · "
                f"{selected_ranges:,} coalesced priority-domain range(s) / "
                f"{self._format_bytes(selected_bytes)} including required NTFS metadata"
                if matched_count or selected_ranges or selected_files
                else f"{query_count:,} search term(s) · awaiting verified MFT folder resolution"
            )

        coverage_status = str(
            hypersafe.get("selected_domain_coverage_status") or ""
        ).strip().lower()
        coverage_counts_valid = (
            selected_ranges > 0
            and selected_imaged_ranges
            + selected_partial_ranges
            + selected_unread_ranges
            == selected_ranges
        )
        if priority_plan_unavailable:
            priority_coverage = (
                "Not available · no priority extent domain was used; "
                "the complete source image remains active"
            )
        elif selected_files == 0 and folder_resolution_ready:
            priority_coverage = (
                "Matching folders were found, but no recoverable selected file "
                "records/extents are visible in the currently readable MFT"
            )
        elif coverage_status != "available" or not coverage_counts_valid:
            priority_coverage = (
                "Priority-domain coverage assessment unavailable or still pending"
            )
        else:
            priority_coverage = (
                f"{selected_imaged_ranges:,}/{selected_ranges:,} coalesced ranges fully imaged · "
                f"{selected_partial_ranges:,} partial · "
                f"{selected_unread_ranges:,} unread · "
                f"{self._format_bytes(selected_imaged_bytes)} imaged · "
                f"{self._format_bytes(selected_unresolved_bytes)} unresolved"
            )

        priority_complete = max(0, int(facts.get("priority_complete") or 0))
        priority_waiting = max(0, int(facts.get("priority_waiting") or 0))
        priority_failed = max(0, int(facts.get("priority_failed") or 0))
        priority_unaccounted = max(
            0, int(facts.get("priority_unaccounted") or 0)
        )
        priority_output_folders = max(
            0, int(facts.get("priority_output_folders") or 0)
        )
        image_only = self._map_int(hypersafe, "image_only") == 1
        if priority_plan_unavailable:
            priority_result = (
                "Not attempted · priority metadata was unavailable; "
                "full-source imaging continues"
            )
        elif image_only:
            priority_result = (
                "Not requested · image-only mode keeps recovered data in the image"
            )
        elif not folder_resolution_ready and selected_files == 0:
            priority_result = (
                "Pending until MFT folder resolution and the priority plan are ready"
            )
        elif selected_files == 0:
            priority_result = (
                "No selected file records were available for reconstruction"
            )
        else:
            folder_output_text = (
                f"{priority_output_folders:,}/{matched_count:,} "
                "matching MFT folder(s) produced complete files"
                if folder_resolution_ready
                else f"{priority_output_folders:,} matching folder(s) produced complete files"
            )
            priority_result = (
                f"{priority_complete:,}/{selected_files:,} complete · "
                f"{priority_waiting:,} waiting for readable extents · "
                f"{priority_failed:,} failed validation/write · "
                f"{priority_unaccounted:,} not yet accounted · "
                f"{folder_output_text}"
            )

        def readable_step_status(key: str) -> str:
            return str(hypersafe.get(key) or "pending").strip().replace(
                "_", " "
            )

        def pass_summary(
            label: str,
            status_key: str,
            bytes_key: str,
            known_key: str,
        ) -> str:
            status = readable_step_status(status_key)
            if status in {"pending", "running", "not required"}:
                return f"{label} {status}"
            if self._map_int(hypersafe, known_key) == 1:
                return (
                    f"{label} {status} "
                    f"(+{self._format_bytes(self._map_int(hypersafe, bytes_key))})"
                )
            return f"{label} {status} (coverage delta unavailable)"

        priority_retries = (
            f"{pass_summary('priority quick', 'selected_quick_read_status', 'selected_quick_new_bytes', 'selected_quick_new_bytes_known')} · "
            f"{pass_summary('whole-source quick', 'quick_image_pass_status', 'full_quick_selected_new_bytes', 'full_quick_selected_new_bytes_known')} · "
            f"{pass_summary('forward x2', 'selected_retry_forward_status', 'selected_retry_forward_new_bytes', 'selected_retry_forward_new_bytes_known')} · "
            f"{pass_summary('reverse x1', 'selected_retry_reverse_status', 'selected_retry_reverse_new_bytes', 'selected_retry_reverse_new_bytes_known')} · "
            f"remaining whole-source {readable_step_status('global_retry_status')}"
        )
        presentation["priority_sections"] = [
            ("PRIORITY SEARCH / PLAN", priority_plan),
            ("PRIORITY IMAGE COVERAGE", priority_coverage),
            (
                "FILE RECOVERY" if image_only else "PRIORITY RECOVERY RESULT",
                priority_result,
            ),
            ("PRIORITY RETRY PASSES", priority_retries),
        ]
        return presentation

    @staticmethod
    def _activity_ddrescue_operation(facts: dict) -> str:
        """Describe a supervisor condition without mixing copy into state I/O."""
        status = str(facts.get("status") or "").strip().lower()
        phase = str(facts.get("phase") or "ddrescue image pass").strip()
        blocked_seconds = max(0, int(facts.get("blocked_seconds") or 0))
        if status == "kernel_io_hang":
            return (
                f"KERNEL I/O HANG · {phase} · map saved · "
                "reboot Ubuntu before resume"
            )
        if status == "watching_kernel_io_stall":
            return (
                f"Slow kernel I/O · D-state {blocked_seconds}s · Carv is "
                "still watching because no kernel crash is confirmed"
            )
        return ""

    def _update_operator_activity(
        self,
        state_dir: Path,
        activity: dict,
        *,
        phase: str,
        offset: int,
        total: int,
        recovered: int,
    ) -> None:
        """Render only operator-relevant facts backed by live run state."""
        presentation = {}
        hypersafe_facts = activity.get("activity.hypersafe")
        if isinstance(hypersafe_facts, dict):
            presentation = self._activity_hypersafe_presentation(
                hypersafe_facts
            )
        mode = str(activity.get("mode") or "").strip().lower()
        if mode in {"folders", "folder", "filesystem"}:
            position_heading = "RECOVERY DATA PROGRESS"
            progress_age_heading = "LAST ACTIVITY"
            position = max(
                0,
                self._map_int(
                    activity,
                    "recovery.bytes_written",
                    "prefix.bytes_processed",
                    "metadata.bytes_processed",
                ),
            )
        else:
            position_heading = "SOURCE POSITION"
            progress_age_heading = "LAST ACTIVITY"
            position = max(0, int(offset or 0))
        position_heading_override = str(
            presentation.get("position_heading") or ""
        ).strip()
        if position_heading_override:
            position_heading = position_heading_override

        now = time.monotonic()
        progress_marker = position
        if mode in {"folders", "folder", "filesystem"}:
            progress_marker += max(
                0,
                self._map_int(
                    activity,
                    "recovery.jobs_completed",
                    "scan.recovered_files",
                ),
            )
            progress_marker += max(
                0,
                self._map_int(activity, "recovery.files_incomplete"),
            )
            progress_marker += max(
                0,
                self._map_int(activity, "recovery.files_failed"),
            )
        if progress_marker > self._activity_last_position:
            self._activity_last_position = progress_marker
            self._activity_last_progress_at = now

        position_text = self._format_bytes(position)
        if total > 0:
            position_text += f" / {self._format_bytes(total)}"

        snapshot = self._evidence_cache.get("data")
        skip_kinds = {"deferred", "forced_skip", "skipped", "coverage_gap", "unread"}
        fresh_errors = []
        fresh_skipped = []
        if isinstance(snapshot, DiskMapSnapshot):
            fresh_errors.extend(snapshot.errors)
            fresh_skipped.extend(snapshot.skipped)
        # gui_trouble_evidence.tsv is small and authoritative for live trouble.
        # Read it independently of the slower File findings refresh so Activity
        # cannot claim that the source is clean while the event log is already
        # reporting problem zones.
        for row in self._read_tsv_rows(
            self._evidence_artifact(state_dir, "gui_trouble_evidence.tsv"),
            (
                "pass_id", "start_offset", "end_offset", "kind", "hit_count",
                "first_seen_unix", "last_seen_unix",
            ),
        ):
            kind = str(row.get("kind") or "read_fail").strip().lower()
            segment = self._range_segment(
                row,
                kind=kind,
                source="gui_trouble_evidence.tsv",
                count=max(1, self._map_int(row, "hit_count", default=1)),
            )
            if segment is not None:
                (fresh_skipped if kind in skip_kinds else fresh_errors).append(segment)
        if fresh_errors:
            self._activity_known_error_segments = self._dedupe_map_segments(
                fresh_errors + self._activity_known_error_segments
            )
        if fresh_skipped:
            self._activity_known_skipped_segments = self._dedupe_map_segments(
                fresh_skipped + self._activity_known_skipped_segments
            )

        error_zones = skipped_zones = error_bytes = skipped_bytes = 0
        latest_problem = None
        latest_problem_label = ""
        last_problem_text = "No read errors or skipped ranges recorded"
        if self._activity_known_error_segments or self._activity_known_skipped_segments:
            errors = self._merge_spans(
                (item.start_offset, item.end_offset)
                for item in self._activity_known_error_segments
            )
            skipped = self._merge_spans(
                (item.start_offset, item.end_offset)
                for item in self._activity_known_skipped_segments
            )
            error_zones = len(errors)
            skipped_zones = len(skipped)
            error_bytes = sum(end - start for start, end in errors)
            skipped_bytes = sum(end - start for start, end in skipped)
            problem_snapshot = DiskMapSnapshot()
            problem_snapshot.errors = list(self._activity_known_error_segments)
            problem_snapshot.skipped = list(self._activity_known_skipped_segments)
            latest_problem, latest_problem_label = self._latest_problem_segment(problem_snapshot)
        if error_zones or skipped_zones:
            condition_parts = []
            if error_zones:
                condition_parts.append(
                    f"{error_zones:,} read-error zone(s) · {self._format_bytes(error_bytes)}"
                )
            if skipped_zones:
                condition_parts.append(
                    f"{skipped_zones:,} skipped range(s) · {self._format_bytes(skipped_bytes)}"
                )
            source_condition = " · ".join(condition_parts)
            if latest_problem is not None:
                last_problem_text = self._problem_segment_text(
                    latest_problem,
                    latest_problem_label,
                    error_zones=error_zones,
                    error_bytes=error_bytes,
                    skipped_zones=skipped_zones,
                    skipped_bytes=skipped_bytes,
                )
                problem_signature = (
                    f"{latest_problem_label}:{latest_problem.start_offset}:"
                    f"{latest_problem.end_offset}:{latest_problem.kind}:"
                    f"{latest_problem.source}:{error_zones}:{error_bytes}:"
                    f"{skipped_zones}:{skipped_bytes}"
                )
                if problem_signature != self._activity_last_problem_signature:
                    self._activity_last_problem_signature = problem_signature
                    self._append_gui_event(
                        "read_problem",
                        detail=last_problem_text,
                    )
        elif isinstance(snapshot, DiskMapSnapshot):
            source_condition = "No read errors or skipped ranges recorded"
        else:
            source_condition = "Waiting for file findings"
            last_problem_text = "Waiting for file findings"

        completed = max(
            recovered,
            self._map_int(activity, "recovery.jobs_completed", "scan.recovered_files"),
        )
        bytes_written = self._map_int(activity, "recovery.bytes_written")
        recovered_text = f"{completed:,} file(s)"
        if bytes_written > 0:
            recovered_text += f" · {self._format_bytes(bytes_written)} written"
        incomplete = self._map_int(activity, "recovery.files_incomplete")
        failed = self._map_int(activity, "recovery.files_failed")
        if incomplete > 0:
            recovered_text += f" · {incomplete:,} incomplete"
        if failed > 0:
            recovered_text += f" · {failed:,} failed"

        queued = max(
            0,
            self._map_int(activity, "write_queue.count", "async.queue_count"),
        )
        active = max(0, self._map_int(activity, "async.active_jobs"))
        write_text = f"{queued:,} queued"
        if active:
            write_text = f"{active:,} active · {write_text}"
        elif queued == 0:
            write_text = "Idle · 0 queued"

        latest_output = self._latest_recovered_output(state_dir, completed) or "No recovered output yet"
        latest_event = self._last_nonempty_line(
            self._evidence_artifact(state_dir, "runtime_events.log")
        )
        latest_event = self._sanitize_process_text(latest_event)
        source_condition_override = str(
            presentation.get("source_condition") or ""
        ).strip()
        if source_condition_override:
            source_condition = source_condition_override
        latest_event_override = str(
            presentation.get("latest_event") or ""
        ).strip()
        if latest_event_override:
            latest_event = latest_event_override
        if len(latest_event) > 180:
            latest_event = latest_event[:177].rstrip() + "…"

        operation = str(activity.get("scan.activity") or phase or "Starting").strip()
        if operation.lower() in {"folders", "folder", "filesystem"}:
            operation = "Reading filesystem metadata and selected file extents"
        elif operation.lower() == "all":
            operation = "Sequential source scan"
        ddrescue_facts = activity.get("activity.ddrescue")
        if isinstance(ddrescue_facts, dict):
            ddrescue_operation = self._activity_ddrescue_operation(
                ddrescue_facts
            )
            if ddrescue_operation:
                operation = ddrescue_operation
        if not latest_event and latest_output != "No recovered output yet":
            latest_event = f"Recovered {latest_output}"
        current_path = str(activity.get("recovery.current_path") or "").strip()
        ddrescue_progress = str(getattr(self, "_event_log_progress_text", "") or "").strip()
        revisit = self._read_state_file(state_dir / "revisit_status.txt")
        revisit_text = ""
        try:
            revisit_started = int(revisit.get("started_unix") or 0)
        except (TypeError, ValueError):
            revisit_started = 0
        try:
            revisit_extra = max(0, int(revisit.get("extra_files") or 0))
        except (TypeError, ValueError):
            revisit_extra = 0
        try:
            revisit_last_complete = int(
                revisit.get("last_complete_file_unix") or 0
            )
        except (TypeError, ValueError):
            revisit_last_complete = 0
        if revisit_started > 0:
            reached_text = datetime.fromtimestamp(revisit_started).strftime(
                "%d %b · %H:%M:%S"
            )
            last_complete_text = (
                datetime.fromtimestamp(revisit_last_complete).strftime(
                    "%d %b · %H:%M:%S"
                )
                if revisit_last_complete > 0
                else "none yet"
            )
            revisit_text = (
                f"100% reached {reached_text} · +{revisit_extra:,} extra file(s) "
                f"· last complete file {last_complete_text}"
            )

        priority_sections = presentation.get("priority_sections")
        if not isinstance(priority_sections, list):
            priority_sections = []

        activity_signature = "\x1f".join(
            [
                str(progress_marker),
                str(completed),
                str(bytes_written),
                str(incomplete),
                str(failed),
                str(queued),
                str(active),
                operation,
                current_path,
                latest_output,
                latest_event,
                ddrescue_progress,
                revisit_text,
                *(value for _heading, value in priority_sections),
            ]
        )
        if activity_signature != self._activity_last_signature:
            self._activity_last_signature = activity_signature
            self._activity_last_progress_at = now
        if active > 0 or queued > 0:
            self._activity_last_progress_at = now
        if self._activity_last_progress_at:
            progress_age = max(0, int(now - self._activity_last_progress_at))
            last_activity = (
                "active now"
                if active > 0 or queued > 0
                else "just now"
                if progress_age < 2
                else f"{self._format_duration(progress_age)} ago"
            )
        else:
            last_activity = "waiting for measurable activity"

        sections = [
            ("CURRENT OPERATION", operation),
            (position_heading, position_text),
            (progress_age_heading, last_activity),
            ("SOURCE CONDITION", source_condition),
            ("LAST READ PROBLEM", last_problem_text),
            ("RECOVERY", recovered_text),
            ("LATEST OUTPUT", latest_output),
            ("WRITE PIPELINE", write_text),
            ("LATEST EVENT", latest_event or "No notable event recorded yet"),
        ]
        if revisit_text:
            sections.insert(1, ("POST-SCAN / REVISIT", revisit_text))
        if current_path:
            sections.insert(1, ("CURRENT FILE", current_path))
        insertion_index = next(
            (
                index
                for index, (heading, _value) in enumerate(sections)
                if heading == "RECOVERY"
            ),
            len(sections),
        )
        for heading, value in reversed(priority_sections):
            if value:
                sections.insert(insertion_index, (heading, value))
        self._set_run_activity_body(
            "\n\n".join(f"{heading}\n{value}" for heading, value in sections)
        )

    # End Activity presentation.

    def _update_cumulative_evidence(
        self,
        state_dir: Path,
        source_size: int,
        *,
        scan_offset: int = 0,
        scan_mode: str = "",
        force: bool = False,
    ) -> None:
        now = time.monotonic()
        stage_hint = self._read_state_file(state_dir / "raw_all_stage.txt")
        backend_hint = str(stage_hint.get("fs_backend") or "").strip().lower()
        hfs_evidence = (
            self._run_progress_authority == "hfsplus"
            or backend_hint == "hfsplus"
        )
        refresh_interval = (
            60.0 if self._run_progress_authority == "hfsplus"
            else 30.0 if hfs_evidence
            else 10.0
        )
        if (
            not force
            and self._evidence_cache.get("data") is not None
            and now - self._last_evidence_refresh_at < refresh_interval
        ):
            return
        self._last_evidence_refresh_at = now
        paths = tuple(
            self._evidence_artifact(state_dir, name)
            for name in (
                "gui_passes.tsv", "gui_read_coverage.tsv",
                "gui_recovery_evidence.tsv", "gui_trouble_evidence.tsv",
                "hfsplus_recovery_failures.tsv",
                "recovered_outputs.tsv", "read_trouble_map.tsv",
                "deferred_bad_zones.tsv", "source_image_bad_ranges.tsv",
                "last_bad_read.txt", "coverage_gaps.tsv",
                "coverage_gap_observations.tsv", "read_errors.tsv",
                "mft_map.c26mft", "runtime_events.log", "thread_activity.txt",
            )
        )
        stamp_parts = []
        for path in paths:
            try:
                stat = path.stat()
                stamp_parts.append((str(path), stat.st_mtime_ns, stat.st_size))
            except OSError:
                stamp_parts.append((str(path), None, None))
        recovered_root = state_dir.parent / "recovered"
        try:
            recovered_stamp = recovered_root.stat().st_mtime_ns
        except OSError:
            recovered_stamp = None
        geometry_stamp = tuple(sorted((str(key), int(value)) for key, value in self._run_ntfs_geometry.items()))
        active_scope_stamp = self._active_run_scope_from_command(source_size)
        stamp = tuple(stamp_parts) + (
            recovered_stamp,
            max(0, int(source_size or 0)),
            max(0, int(scan_offset or 0)) // (1024 * 1024 * 1024),
            str(scan_mode or ""),
            geometry_stamp,
            active_scope_stamp,
        )
        if (
            not force
            and self._evidence_cache.get("stamp") == stamp
            and self._evidence_cache.get("data") is not None
        ):
            snapshot = self._evidence_cache["data"]
        else:
            snapshot = self._build_disk_map_snapshot(
                state_dir,
                source_size=max(0, int(source_size or 0)),
                scan_offset=max(0, int(scan_offset or 0)),
                scan_mode=str(scan_mode or ""),
            )
            self._evidence_cache = {"stamp": stamp, "data": snapshot}

        if snapshot.source_size <= 0:
            self.run_evidence_map.clear()
            self.run_evidence_summary.setText("Waiting for file findings")
            self.run_evidence_summary.setToolTip(str(state_dir))
            return
        self.run_evidence_map.set_snapshot(snapshot)
        self.run_evidence_summary.setText(self._disk_map_summary(snapshot))
        tooltip = [f"File findings: {state_dir}"]
        tooltip.extend(snapshot.notes)
        self.run_evidence_summary.setToolTip("\n".join(tooltip))

    def _schedule_hfs_evidence_refresh(
        self,
        state_dir: Path,
        source_size: int,
        *,
        scan_offset: int,
        scan_mode: str,
    ) -> None:
        """Yield one paint cycle before rebuilding a large live HFS+ map."""
        if self._hfs_evidence_refresh_pending:
            return
        self._hfs_evidence_refresh_pending = True

        def refresh() -> None:
            self._hfs_evidence_refresh_pending = False
            if self._shutdown_started:
                return
            saved_backend = str(self._read_state_file(
                state_dir / "hfsplus_recovery_progress.txt"
            ).get("backend") or "").strip().lower()
            if self._run_progress_authority != "hfsplus" and saved_backend != "hfsplus":
                return
            self._update_cumulative_evidence(
                state_dir,
                source_size,
                scan_offset=scan_offset,
                scan_mode=scan_mode,
            )

        QTimer.singleShot(50, refresh)

    @staticmethod
    def _mft_visible_component_name(component: str) -> str:
        text = (component or "").strip().strip("\\/")
        if not text:
            return ""
        aliases = {
            "$recycle.bin": "Recycle.Bin",
            "recycler": "_Recycler",
            "recycled": "_Recycled",
            "system volume information": "_System Volume Information",
        }
        lower = text.lower()
        if lower in aliases:
            return aliases[lower]
        if text.startswith("$") and len(text) > 1 and lower not in MFT_INTERNAL_COMPONENT_NAMES:
            return text[1:]
        return text

    def _load_mftprobe_map_entries(self, path: Path):
        """Read the durable MFT map used by the original GUI evidence fallback."""
        try:
            raw = path.read_bytes()
        except OSError:
            return []
        if len(raw) < 8:
            return []

        def rd16(buf, offset):
            return struct.unpack_from("<H", buf, offset)[0]

        def rd32(buf, offset):
            return struct.unpack_from("<I", buf, offset)[0]

        def rd64(buf, offset):
            return struct.unpack_from("<Q", buf, offset)[0]

        def rd_i64(buf, offset):
            return struct.unpack_from("<q", buf, offset)[0]

        legacy = raw.startswith(MFTPROBE_BIN_MAGIC_V1 + b"\x00")
        legacy_header_cluster = rd32(raw, 16) if legacy and len(raw) >= 20 else 0
        cursor = MFTPROBE_LEGACY_MAP_HEADER_SIZE if legacy else 0
        entries = []
        while cursor < len(raw):
            if legacy:
                if cursor + 8 > len(raw) or raw[cursor:cursor + 4] != MFTPROBE_LEGACY_RECORD_MAGIC:
                    break
                payload_len = rd32(raw, cursor + 4)
                cursor += 8
                if payload_len < MFTPROBE_LEGACY_MAP_RECORD_FIXED_SIZE or cursor + payload_len > len(raw):
                    break
                payload = raw[cursor:cursor + payload_len]
                cursor += payload_len
                run_count = min(rd32(payload, 112), 64)
                name_len = rd16(payload, 116)
                needed = MFTPROBE_LEGACY_MAP_RECORD_FIXED_SIZE + name_len + (run_count * 16)
                if name_len <= 0 or needed > payload_len:
                    continue
                binary_flags = rd32(payload, 20)
                name_start = MFTPROBE_LEGACY_MAP_RECORD_FIXED_SIZE
                runs_cursor = name_start + name_len
                runs = []
                for _ in range(run_count):
                    runs.append((rd64(payload, runs_cursor), rd64(payload, runs_cursor + 8)))
                    runs_cursor += 16
                resident = bool(binary_flags & 0x00000008)
                first_lcn, run_clusters = rd64(payload, 96), rd64(payload, 104)
                if not resident and first_lcn > 0 and run_clusters > 0 and not runs:
                    runs.append((first_lcn, run_clusters))
                entries.append({
                    "record": rd64(payload, 0), "parent": rd64(payload, 8),
                    "offset": rd64(payload, 40), "data_size": rd64(payload, 72),
                    "data_offset": rd_i64(payload, 48), "resident": resident,
                    "volume_offset": 0, "cluster_size": 0, "map_version": 0,
                    "name": payload[name_start:name_start + name_len].decode("utf-8", errors="replace"),
                    "runs": runs,
                })
                continue

            if cursor + MFTPROBE_BIN_ROW_SIZE_V1 > len(raw):
                break
            magic = raw[cursor:cursor + 7]
            if magic == MFTPROBE_BIN_MAGIC_V3:
                fixed_size, version = MFTPROBE_BIN_ROW_SIZE_V3, 3
            elif magic == MFTPROBE_BIN_MAGIC_V2:
                fixed_size, version = MFTPROBE_BIN_ROW_SIZE_V2, 2
            elif magic == MFTPROBE_BIN_MAGIC_V1:
                fixed_size, version = MFTPROBE_BIN_ROW_SIZE_V1, 1
            else:
                break
            if cursor + fixed_size > len(raw):
                break
            row = raw[cursor:cursor + fixed_size]
            cursor += fixed_size
            name_len = rd16(row, 34)
            if name_len <= 0 or name_len >= 4096 or cursor + name_len > len(raw):
                break
            name = raw[cursor:cursor + name_len].decode("utf-8", errors="replace")
            cursor += name_len
            run_count = min(rd32(row, 140), 64) if version >= 3 else 0
            runs = []
            for _ in range(run_count):
                if cursor + 16 > len(raw):
                    break
                runs.append((rd64(raw, cursor), rd64(raw, cursor + 8)))
                cursor += 16
            first_lcn, run_clusters = rd64(row, 52), rd64(row, 60)
            resident = rd_i64(row, 36) >= 0 and first_lcn == 0
            if version < 3 and first_lcn > 0 and run_clusters > 0 and not runs:
                runs.append((first_lcn, run_clusters))
            entries.append({
                "record": rd32(row, 16), "parent": rd64(row, 20),
                "offset": rd64(row, 8), "data_size": rd64(row, 44),
                "data_offset": rd_i64(row, 36), "resident": resident,
                "volume_offset": rd64(row, 104) if version >= 2 else 0,
                "cluster_size": rd64(row, 112) if version >= 2 else 0,
                "map_version": version,
                "name": name, "runs": runs,
            })

        # Legacy rows predate embedded per-volume geometry.  Reconstruct it
        # from each volume's $MFT row: the row offset is absolute source space,
        # while its first run is volume-relative LCN space.  $MFT data size and
        # run cluster count also provide a stronger cluster-size value than the
        # historical 4096-byte header fallback.  A record-number reset to zero
        # starts the next NTFS volume in multi-partition images.
        current_volume_offset = None
        current_cluster_size = 0
        for entry in entries:
            if int(entry.get("map_version") or 0) != 0:
                continue
            name = str(entry.get("name") or "").strip().lower()
            runs = list(entry.get("runs") or [])
            if int(entry.get("record") or 0) == 0 and name == "$mft" and runs:
                run_clusters = sum(max(0, int(clusters)) for _lcn, clusters in runs)
                data_size = max(0, int(entry.get("data_size") or 0))
                inferred_cluster = 0
                if run_clusters > 0 and data_size > 0 and data_size % run_clusters == 0:
                    candidate = data_size // run_clusters
                    if 512 <= candidate <= (2 * 1024 * 1024) and candidate & (candidate - 1) == 0:
                        inferred_cluster = candidate
                current_cluster_size = inferred_cluster or legacy_header_cluster
                first_lcn = max(0, int(runs[0][0]))
                mft_offset = max(0, int(entry.get("offset") or 0))
                relative_mft_offset = first_lcn * current_cluster_size
                current_volume_offset = (
                    mft_offset - relative_mft_offset
                    if current_cluster_size > 0 and mft_offset >= relative_mft_offset
                    else None
                )
            if current_volume_offset is not None and current_cluster_size > 0:
                entry["volume_offset"] = current_volume_offset
                entry["cluster_size"] = current_cluster_size
                entry["geometry_confidence"] = "derived from legacy $MFT"

        by_record = {}
        for index, entry in enumerate(entries):
            by_record.setdefault(int(entry["record"]), []).append(index)
        component_cache = {}

        def components(index, seen=None):
            if index in component_cache:
                return list(component_cache[index])
            seen = set(seen or ())
            if index in seen:
                return []
            seen.add(index)
            entry = entries[index]
            result = []
            parent = int(entry.get("parent") or 0)
            record = int(entry.get("record") or 0)
            if parent > 0 and parent != record and by_record.get(parent):
                result.extend(components(by_record[parent][0], seen))
            name = self._mft_visible_component_name(str(entry.get("name") or ""))
            if name and name not in (".", ".."):
                result.append(name.replace("$", "_"))
            component_cache[index] = tuple(result)
            return result

        for index, entry in enumerate(entries):
            entry["recovered_relpath"] = "/".join(components(index))
        return entries

    def _load_folders_recovered_segments(self, state_dir: Path):
        entries = self._load_mftprobe_map_entries(state_dir / "mft_map.c26mft")
        if not entries:
            return [], set(), set(), []
        geometry = self._runtime_ntfs_geometry(state_dir)
        fallback_cluster = max(0, int(geometry.get("cluster_size") or 0))
        fallback_volume = max(0, int(geometry.get("preferred_volume_offset") or 0))
        recovered_root = state_dir.parent / "recovered"
        segments = []
        positioned_paths = set()
        recovered_paths = set()
        unpositioned_paths = set()
        for entry in entries:
            relpath = str(entry.get("recovered_relpath") or "").strip("/")
            output_path = recovered_root / relpath
            try:
                remaining = output_path.stat().st_size if relpath and output_path.is_file() else 0
            except (OSError, ValueError):
                continue
            if remaining <= 0:
                continue
            original_size = remaining
            label = str(output_path.relative_to(recovered_root))
            recovered_paths.add(label)
            if entry.get("resident"):
                record_offset = max(0, int(entry.get("offset") or 0))
                data_offset = max(0, int(entry.get("data_offset") or 0))
                if record_offset > 0:
                    start = record_offset + data_offset
                    segments.append(DiskMapSegment(
                        start, start + original_size, "span", "resident file",
                        "exact", "mft_map.c26mft", label,
                    ))
                    positioned_paths.add(label)
                else:
                    unpositioned_paths.add(label)
                continue
            entry_cluster = max(0, int(entry.get("cluster_size") or 0))
            if entry_cluster > 0:
                cluster_size = entry_cluster
                # Zero is a valid volume origin in v2/v3 maps and must not be
                # replaced by a runtime geometry from another NTFS volume.
                volume_offset = max(0, int(entry.get("volume_offset") or 0))
            else:
                cluster_size = fallback_cluster
                volume_offset = fallback_volume
            if cluster_size > 0 and entry.get("runs"):
                geometry_confidence = str(entry.get("geometry_confidence") or "exact")
                for lcn, clusters in entry.get("runs", []):
                    extent = min(remaining, max(0, int(clusters)) * cluster_size)
                    if extent <= 0:
                        continue
                    start = volume_offset + max(0, int(lcn)) * cluster_size
                    segments.append(DiskMapSegment(
                        start, start + extent, "span", "file extent", geometry_confidence,
                        "mft_map.c26mft", label,
                    ))
                    remaining -= extent
                    if remaining <= 0:
                        break
                positioned_paths.add(label)
            else:
                # A non-resident file's MFT record is metadata, not its data.
                # Never place the file at entry.offset when volume geometry is
                # missing; that was the source of false markers near disk start.
                unpositioned_paths.add(label)
        notes = []
        if unpositioned_paths:
            notes.append(
                f"{len(unpositioned_paths):,} recovered file(s) lack trustworthy legacy volume geometry and were not given a false disk position."
            )
        return self._dedupe_map_segments(segments), positioned_paths, recovered_paths, notes

    def _load_legacy_evidence(self, state_dir: Path):
        scan = self._read_state_file(state_dir / "scan_state.txt")
        snapshot = self._build_disk_map_snapshot(
            state_dir,
            source_size=max(0, self._map_int(scan, "source_size")),
            scan_offset=max(0, self._map_int(scan, "scan_offset")),
            scan_mode=str(scan.get("scan_mode") or ""),
        )
        recovery = [
            (item.start_offset, item.end_offset, item.geometry)
            for item in snapshot.recovered
        ]
        trouble = [
            (item.start_offset, item.end_offset, item.geometry)
            for item in snapshot.errors + snapshot.skipped
        ]
        return recovery, trouble

    def _safe_update_run_from_state(self, force_evidence: bool = False) -> None:
        try:
            self._update_run_from_state(force_evidence=force_evidence)
        except PermissionError as exc:
            now = time.monotonic()
            if now - self._last_state_monitor_permission_warning_at >= 10.0:
                self._last_state_monitor_permission_warning_at = now
                self._append_gui_event(
                    "state_monitor_permission",
                    error=exc,
                )
            self._set_live_monitor_status("state permission pending")
        except OSError as exc:
            now = time.monotonic()
            if now - self._last_state_monitor_permission_warning_at >= 10.0:
                self._last_state_monitor_permission_warning_at = now
                self._append_gui_event(
                    "state_monitor_read_error",
                    error=exc,
                )
            self._set_live_monitor_status("state read retrying")

    def _current_ddrescue_supervisor_state(self) -> dict:
        if self._current_run_dir is None:
            return {}
        run_dir = self._resolve_live_run_directory()
        if run_dir is None:
            return {}
        path = run_dir / "state" / "ddrescue_supervisor.txt"
        stat = self._path_stat(path)
        if stat is None:
            return {}
        if (
            self._run_started_wall_time
            and stat.st_mtime < self._run_started_wall_time - 1.0
        ):
            return {}
        state = self._read_state_file(path)
        status = str(state.get("status") or "").strip().lower()
        return state if status in {
            "watching_kernel_io_stall",
            "kernel_io_hang",
        } else {}

    def _finish_kernel_io_hang_monitor(self, return_code: int, state: dict) -> None:
        self._process_timer.stop()
        self._run_busy_timer.stop()
        if self._process_reader_thread is not None:
            # A D-state ddrescue descendant still owns the inherited output
            # pipe. Never block Qt waiting for that kernel-owned descriptor.
            self._process_reader_thread.join(timeout=0.05)
        # State was already refreshed in this poll. Do not force a potentially
        # expensive evidence rebuild while reporting an operating-system hang.
        self._safe_update_run_from_state(force_evidence=False)
        self._record_run_elapsed(return_code)
        self._kernel_reboot_required = True
        self._stop_requested = True
        self.stop_button.setText("REBOOT REQUIRED")
        self.stop_button.setEnabled(False)
        self.stop_button.setToolTip(
            "The Linux storage path crashed. Reboot before resuming this Service ID."
        )
        self.continue_image_button.setVisible(False)
        self.continue_image_button.setEnabled(False)
        self.run_state_value.setText("●  KERNEL I/O HANG")
        self.run_state_value.setStyleSheet(
            f"color: #ff6975; font-family: '{mono_font_family()}'; font-size: 10px; "
            "font-weight: 800; letter-spacing: 1px; border: none;"
        )
        self.run_monitor_status.setText("MAP SAVED · REBOOT UBUNTU BEFORE RESUME")
        phase = str(state.get("phase") or "ddrescue image pass").strip()
        blocked = str(state.get("blocked_seconds") or "?").strip()
        self.run_metric_values["PHASE"].setText(
            f"Kernel I/O hang during {phase}"
        )
        self.run_metric_values["STALLED"].setText(
            f"D-state {blocked}s · reboot required"
        )
        self._append_gui_event("kernel_io_hang")
        self._process = None
        self._process_started_with_sudo = False
        self._refresh_plan_status()

    def _poll_recovery_process(self) -> None:
        try:
            self._poll_recovery_process_guarded()
        except Exception as exc:
            # PyQt6 treats an exception escaping a timer callback as fatal and
            # calls abort().  The recovery process and its output must survive
            # a presentation/monitoring bug, so never let one cross this slot.
            details = "".join(
                traceback.format_exception(type(exc), exc, exc.__traceback__)
            ).rstrip()
            try:
                self._append_gui_event("monitor_error", details=details)
                self.run_monitor_status.setText("MONITOR ERROR · RECOVERY OUTPUT INTACT")
            except Exception:
                print(details, file=sys.stderr, flush=True)
            process = self._process
            if process is not None and process.poll() is not None:
                self._process_timer.stop()
                self._run_busy_timer.stop()
                self.stop_button.setEnabled(False)
                self.run_state_value.setText("●  GUI MONITOR ERROR")
                self._process = None

    def _poll_recovery_process_guarded(self) -> None:
        process = self._process
        if process is None:
            self._process_timer.stop()
            self._run_busy_timer.stop()
            return
        with self._process_output_lock:
            lines = list(self._process_output)
            self._process_output.clear()
        for line in lines:
            if line.startswith(DDRESCUE_PROGRESS_EVENT_PREFIX):
                progress_text = line[len(DDRESCUE_PROGRESS_EVENT_PREFIX):]
                self._set_event_log_progress(progress_text)
                for progress_line in progress_text.splitlines():
                    self._capture_live_metrics(progress_line)
                continue
            self._append_event_log(line)
            self._capture_live_metrics(line)
        self._safe_update_run_from_state()
        self._refresh_done_live_from_state()
        live_family, _ = self._refresh_recovery_process_family()
        return_code = process.poll()
        if return_code is None:
            self._recovery_launcher_exit_seen_at = 0.0
            return
        ddrescue_supervisor = self._current_ddrescue_supervisor_state()
        if str(ddrescue_supervisor.get("status") or "").strip().lower() == "kernel_io_hang":
            self._finish_kernel_io_hang_monitor(return_code, ddrescue_supervisor)
            return
        lingering = live_family - {process.pid}
        if lingering:
            now = time.monotonic()
            if self._recovery_launcher_exit_seen_at <= 0.0:
                self._recovery_launcher_exit_seen_at = now
                self._append_gui_event("launcher_exited")
                return
            if now - self._recovery_launcher_exit_seen_at < 2.0:
                return
            if not self._recovery_lingering_reported:
                self._recovery_lingering_reported = True
                self._append_gui_event(
                    "recovery_workers_alive",
                    pids=sorted(lingering),
                )
            self._stop_requested = True
            self.stop_button.setText("KILL RECOVERY")
            self.stop_button.setEnabled(True)
            self.stop_button.setToolTip(
                "The launcher exited but recovery descendants remain. Click to force-kill them."
            )
            self.run_state_value.setText("●  STOP PENDING")
            return
        self._process_timer.stop()
        self._run_busy_timer.stop()
        if self._process_reader_thread is not None:
            self._process_reader_thread.join(timeout=0.2)
        with self._process_output_lock:
            final_lines = list(self._process_output)
            self._process_output.clear()
        for line in final_lines:
            if line.startswith(DDRESCUE_PROGRESS_EVENT_PREFIX):
                progress_text = line[len(DDRESCUE_PROGRESS_EVENT_PREFIX):]
                self._set_event_log_progress(progress_text)
                for progress_line in progress_text.splitlines():
                    self._capture_live_metrics(progress_line)
                continue
            self._append_event_log(line)
            self._capture_live_metrics(line)
        self._safe_update_run_from_state(force_evidence=True)
        self._append_gui_event("process_exited", return_code=return_code)
        self._record_run_elapsed(return_code)
        self.stop_button.setEnabled(False)
        self.continue_image_button.setVisible(False)
        self.continue_image_button.setEnabled(False)
        self._refresh_done_from_run(return_code)
        if self._stop_requested:
            run_state, run_color = "●  ABORTED", "#d5a84b"
        elif return_code == 0:
            run_state, run_color = "●  DONE", ACCENT
        else:
            run_state, run_color = "●  ERROR", "#e06b75"
        self.run_state_value.setText(run_state)
        self.run_state_value.setStyleSheet(
            f"color: {run_color}; font-family: '{mono_font_family()}'; font-size: 10px; "
            "font-weight: 800; letter-spacing: 1px; border: none;"
        )
        self.run_monitor_status.setText(f"MONITOR STOPPED · EXIT {return_code}")
        self._process = None
        self._process_started_with_sudo = False
        self._recovery_known_pids.clear()
        self._recovery_known_pgids.clear()
        self._refresh_plan_status()
        self.main_tabs.setCurrentIndex(2)

    def _capture_live_metrics(self, line: str) -> None:
        line = self._sanitize_process_text(line).replace("\r", " ").replace("\n", " ").strip()
        if not line:
            return
        metrics = dict(self._live_metrics)
        geometry_match = re.search(
            r"NTFS geometry:\s*preferred_volume_offset=(\d+)\s+cluster_size=(\d+)",
            line,
            re.IGNORECASE,
        )
        if geometry_match:
            self._run_ntfs_geometry = {
                "preferred_volume_offset": int(geometry_match.group(1)),
                "cluster_size": int(geometry_match.group(2)),
            }
            self._evidence_cache = {"stamp": None, "data": None}
        position_match = re.search(r"\bpos=(\d+)(?:/(\d+))?\s+MiB\b", line, re.IGNORECASE)
        progress_line = bool(
            position_match
            or re.search(
                r"\b(?:speed|eta|phase|stalled|carved|named|unnamed|bg|note)=",
                line,
                re.IGNORECASE,
            )
        )
        percent_match = (
            re.search(r"(?<![\d.])(\d+(?:\.\d+)?)%", line)
            if progress_line else None
        )
        if percent_match:
            metrics["percent"] = float(percent_match.group(1))
        if position_match:
            metrics["offset"] = int(position_match.group(1)) * 1024 * 1024
            if position_match.group(2):
                metrics["total"] = int(position_match.group(2)) * 1024 * 1024
        metric_keys = "speed|eta|phase|stalled|carved|named|unnamed|bg|note"
        for key in ("speed", "eta", "phase", "stalled"):
            match = re.search(
                rf"\b{key}=(.*?)(?=\s+(?:{metric_keys})=|$)",
                line,
                re.IGNORECASE,
            )
            if match:
                value = self._sanitize_process_text(match.group(1)).strip(" ,;")
                if value:
                    metrics[key] = value
        for key in ("carved", "named", "unnamed"):
            match = re.search(rf"\b{key}=(\d+)\b", line, re.IGNORECASE)
            if match:
                metrics[key] = int(match.group(1))
        self._live_metrics = metrics

    def _reset_done_live_tree(self, recovered_root: Path | None) -> None:
        if not hasattr(self, "done_recovered_tree"):
            return
        self._done_lazy_generation += 1
        self._done_lazy_jobs.clear()
        with self._done_lazy_results_lock:
            self._done_lazy_results.clear()
        self._done_lazy_timer.stop()
        self._done_live_last_refresh_at = 0.0
        self._done_live_ledger_path = ""
        self._done_live_ledger_pos = 0
        self._done_live_root_path = str(recovered_root or "")
        self._done_live_seen_paths = set()
        self._done_live_dir_items = {}
        self._done_live_dir_counts = {}
        self._done_live_dir_bytes = {}
        self._done_live_files = 0
        self._done_live_bytes = 0
        self._done_live_unidentified = 0
        self._done_live_embedded = 0
        self._done_recovered_root = recovered_root
        self._done_exact_catalog_duplicate_rows = []
        self._done_exact_catalog_duplicate_paths = set()
        self._done_exact_catalog_duplicate_bytes = 0

        tree = self.done_recovered_tree
        tree.clear()
        role = self._done_loaded_role()
        if recovered_root is None:
            root_item = QTreeWidgetItem(["Waiting for recovered output", "0 files live", "0 B"])
            tree.addTopLevelItem(root_item)
        else:
            root_item = QTreeWidgetItem([
                recovered_root.name, "Expand to browse live output", "—"
            ])
            root_item.setData(0, Qt.ItemDataRole.UserRole, str(recovered_root))
            root_item.setData(0, role, False)
            root_item.setToolTip(0, str(recovered_root))
            root_item.addChild(self._done_loading_placeholder())
            tree.addTopLevelItem(root_item)
            self._done_live_dir_items[""] = root_item
            self._done_live_dir_counts[""] = 0
            self._done_live_dir_bytes[""] = 0

        self.done_status_label.setText("RUNNING")
        self.done_status_label.setStyleSheet(
            f"color: #d5a84b; font-family: '{mono_font_family()}'; font-size: 48px; "
            "font-weight: 900; letter-spacing: 3px; border: none;"
        )
        self.done_status_detail.setText("LIVE OUTPUT VIEW  /  RECOVERY ACTIVE")
        service_id = self.service_id_combo.currentText().strip() or (
            self._current_run_dir.name if self._current_run_dir else "—"
        )
        self.done_service_value.setText(service_id)
        if self._run_started_wall_time:
            started = datetime.fromtimestamp(self._run_started_wall_time).strftime("%d %b %Y · %H:%M:%S")
            self.done_finished_value.setText(f"Running since {started}")
        else:
            self.done_finished_value.setText("Running")
        self.done_runtime_value.setText(self._format_duration(self._current_run_elapsed()))
        self.done_runtime_note.setText("Live GUI session timer")
        self.done_stat_values["RECOVERED"].setText("0")
        self.done_stat_notes["RECOVERED"].setText("live recovered counter")
        self.done_stat_values["NAMED"].setText("0")
        self.done_stat_notes["NAMED"].setText("estimated while running")
        self.done_stat_values["UNIDENTIFIED"].setText("0")
        self.done_stat_notes["UNIDENTIFIED"].setText("estimated while running")
        self.done_stat_values["TROUBLE"].setText("—")
        self.done_stat_notes["TROUBLE"].setText("live findings pending")

        selected_source = self._selected_source or {}
        mode_text = self.mode_combo.currentText()
        mode_lower = mode_text.lower()
        if self._mode_text_is_image_only(mode_lower):
            scope = "Full source · ddrescue image only"
        elif self._mode_text_is_raw_hunt(mode_lower):
            scope = "Full source · byte-sequential"
        elif "name" in mode_lower:
            scope = "Existing recovered output"
        else:
            scope = self._active_folder_scope_summary(
                "No folder selection recorded"
            )
        summary = {
            "Source": str(selected_source.get("path") or "—"),
            "Destination": str(self._current_run_dir or "—"),
            "Mode": mode_text,
            "Filesystem": self._done_filesystem_summary(None),
            "Scope": scope,
            "Filters": self._run_filter_summary(),
            "Read": "Starting",
            "Evidence": "Live tree reads one folder level only when opened",
            "Trouble": "Waiting for live file findings",
        }
        for key, value in summary.items():
            self.done_summary_values[key].setText(value)
        self.done_operator_note.setText(
            "The result tree is live and lazy: opening a folder reads only one limited page "
            "in the background. Final totals replace the live counters when recovery exits."
        )
        self.done_output_path_label.setText(str(recovered_root or "—"))
        self._done_output_target = self._current_run_dir
        try:
            self.done_open_output_button.setEnabled(
                bool(self._done_output_target and Path(self._done_output_target).is_dir())
            )
        except (OSError, ValueError):
            self.done_open_output_button.setEnabled(False)
        self._done_summary_text = "\n".join(
            ["RUNNING / LIVE OUTPUT VIEW", f"Service ID: {service_id}"]
            + [f"{key}: {value}" for key, value in summary.items()]
            + ["Operator note: Live output is browsed lazily until the run exits."]
        )
        self.done_report_button.setEnabled(False)

    def _read_done_live_ledger_paths(self, state_dir: Path, *, max_rows: int = 400) -> list[str]:
        path = self._evidence_artifact(state_dir, "recovered_outputs.tsv")
        stat = self._path_stat(path)
        if stat is None or stat.st_size <= 0:
            return []
        path_text = str(path)
        if path_text != self._done_live_ledger_path or stat.st_size < self._done_live_ledger_pos:
            self._done_live_ledger_path = path_text
            self._done_live_ledger_pos = 0

        outputs: list[str] = []
        try:
            with path.open("rb") as handle:
                handle.seek(max(0, int(self._done_live_ledger_pos or 0)))
                for _index in range(max(1, int(max_rows))):
                    before = handle.tell()
                    raw = handle.readline(1024 * 1024)
                    if not raw:
                        break
                    if not raw.endswith(b"\n"):
                        handle.seek(before)
                        break
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line or line.lower().startswith("offset\t"):
                        continue
                    fields = line.split("\t")
                    if len(fields) < 2:
                        continue
                    output_path = self._state_path_text(fields[1])
                    if output_path:
                        outputs.append(output_path)
                self._done_live_ledger_pos = handle.tell()
        except (OSError, ValueError):
            return []
        return outputs

    def _done_live_resolve_output_path(
        self,
        path_text: str,
        recovered_root: Path,
    ) -> tuple[Path | None, list[str]]:
        cleaned = self._state_path_text(path_text)
        if not cleaned:
            return None, []
        try:
            output_path = Path(cleaned)
        except (TypeError, ValueError):
            return None, []

        run_dir = self._current_run_dir
        parts: list[str] = []
        absolute_path: Path | None = output_path if output_path.is_absolute() else None

        if output_path.is_absolute():
            try:
                parts = list(output_path.relative_to(recovered_root).parts)
            except ValueError:
                if run_dir is not None:
                    try:
                        run_parts = list(output_path.relative_to(run_dir).parts)
                        if run_parts and run_parts[0].casefold() == "recovered":
                            run_parts = run_parts[1:]
                        parts = run_parts
                    except ValueError:
                        parts = []
            if not parts:
                normalized = str(output_path).replace("\\", "/")
                marker = "/recovered/"
                marker_at = normalized.casefold().find(marker)
                if marker_at >= 0:
                    parts = self._done_live_relative_parts(normalized[marker_at + len(marker):])
                elif output_path.name:
                    parts = [output_path.name]
        else:
            parts = self._done_live_relative_parts(cleaned)
            if parts and parts[0].casefold() == "recovered":
                parts = parts[1:]
            if parts:
                absolute_path = recovered_root.joinpath(*parts)

        parts = [
            str(part).strip()
            for part in parts
            if str(part).strip() and str(part).strip() not in {".", ".."}
        ]
        if not parts:
            return absolute_path, []
        if absolute_path is None:
            absolute_path = recovered_root.joinpath(*parts)
        return absolute_path, parts

    def _update_done_live_dir_item(self, key: str) -> None:
        item = self._done_live_dir_items.get(key)
        if item is None:
            return
        files = max(0, int(self._done_live_dir_counts.get(key, 0) or 0))
        size = max(0, int(self._done_live_dir_bytes.get(key, 0) or 0))
        if files:
            noun = "file" if files == 1 else "files"
            item.setText(1, f"{files:,} {noun} live")
            item.setText(2, self._format_bytes(size))
        else:
            item.setText(1, "Folder · live" if key else "0 files live")
            item.setText(2, "—" if key else "0 B")

    def _add_done_live_output_path(self, path_text: str, recovered_root: Path) -> bool:
        absolute_path, parts = self._done_live_resolve_output_path(path_text, recovered_root)
        if not parts:
            return False
        seen_key = str(absolute_path) if absolute_path is not None else "/".join(parts)
        if seen_key in self._done_live_seen_paths:
            return False
        self._done_live_seen_paths.add(seen_key)

        role = self._done_loaded_role()
        root_item = self._done_live_dir_items.get("")
        if root_item is None:
            self._reset_done_live_tree(recovered_root)
            root_item = self._done_live_dir_items.get("")
        if root_item is None:
            return False

        parent = root_item
        for depth, part in enumerate(parts[:-1], start=1):
            dir_key = "/".join(parts[:depth])
            child = self._done_live_dir_items.get(dir_key)
            if child is None:
                dir_path = recovered_root.joinpath(*parts[:depth])
                child = QTreeWidgetItem([part, "Folder · live", "—"])
                child.setData(0, Qt.ItemDataRole.UserRole, str(dir_path))
                child.setData(0, role, True)
                child.setToolTip(0, str(dir_path))
                parent.addChild(child)
                self._done_live_dir_items[dir_key] = child
                self._done_live_dir_counts[dir_key] = 0
                self._done_live_dir_bytes[dir_key] = 0
            parent = child

        size = 0
        size_text = "—"
        if absolute_path is not None:
            stat = self._path_stat(absolute_path)
            if stat is not None:
                size = max(0, int(stat.st_size))
                size_text = self._format_bytes(size)
        file_item = QTreeWidgetItem([parts[-1], "File", size_text])
        file_item.setData(
            0,
            Qt.ItemDataRole.UserRole,
            str(absolute_path) if absolute_path is not None else path_text,
        )
        file_item.setData(0, role, True)
        if absolute_path is not None:
            file_item.setToolTip(0, str(absolute_path))
        parent.addChild(file_item)

        self._done_live_files += 1
        self._done_live_bytes += size
        if any(part.casefold() in {"unidentified", "unident"} for part in parts[:-1]):
            self._done_live_unidentified += 1
            lowered_parts = [part.casefold() for part in parts[:-1]]
            if "embedded" in lowered_parts:
                self._done_live_embedded += 1
        for depth in range(0, len(parts)):
            dir_key = "/".join(parts[:depth])
            self._done_live_dir_counts[dir_key] = self._done_live_dir_counts.get(dir_key, 0) + 1
            self._done_live_dir_bytes[dir_key] = self._done_live_dir_bytes.get(dir_key, 0) + size
            self._update_done_live_dir_item(dir_key)
        return True

    def _done_live_metric(self, *pairs) -> int:
        values = []
        for mapping, key in pairs:
            try:
                values.append(max(0, int(float(mapping.get(key, 0) or 0))))
            except (AttributeError, TypeError, ValueError):
                continue
        return max(values, default=0)

    @staticmethod
    def _done_normalized_filesystem_label(value: str) -> str:
        text = str(value or "").strip()
        lowered = text.casefold()
        compact = re.sub(r"\s+", "", lowered)
        if (
            not lowered
            or lowered in {"auto", "auto detect", "detecting", "unknown", "—", "-"}
            or compact in {"unknown/auto", "auto/unknown"}
        ):
            return ""
        if "hfs+" in lowered or "hfsplus" in lowered or "hfsx" in lowered or "apple_hfs" in lowered:
            return "HFS+"
        if "ntfs" in lowered:
            return "NTFS"
        if "exfat" in lowered:
            return "exFAT"
        if "fat32" in lowered or lowered in {"vfat", "msdos", "fat"}:
            return "FAT32"
        if "apfs" in lowered:
            return "APFS"
        return text

    def _done_hfs_progress_is_current(self, state_dir: Path | None) -> bool:
        if state_dir is None:
            return False
        if not self._run_started_wall_time:
            return True
        stat = self._path_stat(state_dir / "hfsplus_recovery_progress.txt")
        if stat is None:
            return False
        return stat.st_mtime >= self._run_started_wall_time - 1.0

    def _done_filesystem_summary(
        self,
        state_dir: Path | None,
        scan: dict | None = None,
        stage: dict | None = None,
        hfs_progress: dict | None = None,
    ) -> str:
        scan = scan or {}
        stage = stage or {}
        hfs_progress = hfs_progress or {}
        for mapping in (stage, scan):
            for key in (
                "filesystem", "filesys", "source_filesystem",
                "source_filesystem_hint", "filesystem_hint",
            ):
                label = self._done_normalized_filesystem_label(mapping.get(key))
                if label:
                    return label

        hfs_backend = self._done_normalized_filesystem_label(hfs_progress.get("backend"))
        if hfs_backend and self._done_hfs_progress_is_current(state_dir):
            return hfs_backend

        selected_source = self._selected_source or {}
        for key in ("_interpreted_filesystem", "_filesystem", "_preview_filesystem", "fs"):
            label = self._done_normalized_filesystem_label(selected_source.get(key))
            if label:
                return label

        label = self._done_normalized_filesystem_label(self.filesystem_combo.currentText())
        return label or "Auto · not reported"

    def _done_live_trouble_from_cache(self) -> tuple[int, int]:
        snapshot = self._evidence_cache.get("data") if isinstance(self._evidence_cache, dict) else None
        if snapshot is None:
            return 0, 0
        trouble_items = list(getattr(snapshot, "errors", []) or []) + list(getattr(snapshot, "skipped", []) or [])
        trouble_union = self._merge_spans(
            (item.start_offset, item.end_offset) for item in trouble_items
        )
        return len(trouble_union), sum(end - start for start, end in trouble_union)

    def _update_done_live_cards(self, state_dir: Path, recovered_root: Path) -> None:
        scan = self._read_state_file(state_dir / "scan_state.txt")
        stage = self._read_state_file(state_dir / "raw_all_stage.txt")
        spool = self._read_state_file(state_dir / "spool_live_stats.txt")
        name_state = self._read_state_file(state_dir / "name_salvage_state.txt")
        hfs_progress = self._read_state_file(state_dir / "hfsplus_recovery_progress.txt")
        hypersafe = self._read_state_file(state_dir / "hypersafe_recovery.txt")

        recovered = self._done_live_metric(
            (spool, "recovered_outputs_current"), (stage, "recovered_files")
        )
        hypersafe_selected = (
            self._state_path_is_current_run(
                state_dir / "hypersafe_recovery.txt"
            )
            and str(hypersafe.get("strategy") or "").strip()
            == "hypersafe_selected_quick_map_retry"
        )
        hypersafe_selected_complete = 0
        if hypersafe_selected:
            hypersafe_selected_complete = max(
                self._done_live_metric((hypersafe, "final_complete")),
                *(
                    self._done_live_metric((hypersafe, f"{prefix}_recovered"))
                    + self._done_live_metric(
                        (hypersafe, f"{prefix}_already_present")
                    )
                    for prefix in ("early", "quick_image", "targeted_retry")
                ),
            )
            recovered = max(
                recovered,
                self._done_live_metric(
                    (hypersafe, "recovered_total"),
                    (hypersafe, "final_complete"),
                ),
            )
        if str(hfs_progress.get("backend") or "").strip().lower() == "hfsplus":
            recovered = max(recovered, self._done_live_metric((hfs_progress, "files_completed")))
        unidentified = max(
            max(0, self._done_live_unidentified - self._done_live_embedded),
            self._done_live_metric(
                (spool, "unident_outputs_current"),
                (spool, "files_still_in_unident"),
                (name_state, "unident_outputs_current"),
                (name_state, "files_still_in_unident"),
            ),
        )
        named = max(
            max(0, recovered - unidentified),
            self._done_live_metric(
                (spool, "named_outputs_current"),
                (spool, "files_outside_unident"),
                (stage, "named_files"),
                (name_state, "named_outputs_current"),
            ),
        )
        if hypersafe_selected:
            named = max(named, hypersafe_selected_complete)
        trouble_zones, trouble_bytes = self._done_live_trouble_from_cache()

        self.done_stat_values["RECOVERED"].setText(f"{recovered:,}")
        self.done_stat_notes["RECOVERED"].setText("durable live counter · tree loads on demand")
        self.done_stat_values["NAMED"].setText(f"{named:,}")
        named_share = (named / recovered * 100.0) if recovered else 0.0
        self.done_stat_notes["NAMED"].setText(f"{named_share:.1f}% estimated" if recovered else "estimated while running")
        self.done_stat_values["UNIDENTIFIED"].setText(f"{unidentified:,}")
        self.done_stat_notes["UNIDENTIFIED"].setText(
            f"live estimate · {self._done_live_embedded:,} embedded contextualized"
            if self._done_live_embedded else "live estimate"
        )
        self.done_stat_values["TROUBLE"].setText(f"{trouble_zones:,}" if trouble_zones else "—")
        self.done_stat_notes["TROUBLE"].setText(
            f"zones · {self._format_bytes(trouble_bytes)}" if trouble_zones else "live findings pending"
        )

        elapsed = self._current_run_elapsed()
        self.done_runtime_value.setText(self._format_duration(elapsed))
        if self._run_started_wall_time:
            started = datetime.fromtimestamp(self._run_started_wall_time).strftime("%d %b %Y · %H:%M:%S")
            self.done_finished_value.setText(f"Running since {started}")

        scope_start = self._done_live_metric((stage, "selected_scope_start_bytes"))
        scope_end = self._done_live_metric((stage, "selected_scope_end_bytes"))
        source_size = max(0, scope_end - scope_start) or self._done_live_metric(
            (stage, "total_bytes"), (scan, "source_size")
        )
        read_offset = self._done_live_metric(
            (stage, "selected_scope_progress_bytes"),
            (stage, "progress_bytes"),
        )
        if not read_offset:
            absolute_offset = self._done_live_metric((scan, "scan_offset"))
            read_offset = max(0, absolute_offset - scope_start)
        read_text = f"{self._format_bytes(read_offset)} read"
        if source_size:
            read_text += f" of {self._format_bytes(source_size)}"
        if str(hfs_progress.get("backend") or "").strip().lower() == "hfsplus":
            hfs_bytes = self._done_live_metric((hfs_progress, "bytes_written"))
            hfs_total = self._done_live_metric((hfs_progress, "bytes_total"))
            if hfs_bytes or hfs_total:
                read_text = f"{self._format_bytes(hfs_bytes)} recovered"
                if hfs_total:
                    read_text += f" of {self._format_bytes(hfs_total)} selected"
        summary_updates = {
            "Destination": str(self._current_run_dir or "—"),
            "Filesystem": self._done_filesystem_summary(state_dir, scan, stage, hfs_progress),
            "Read": read_text,
            "Evidence": f"Lazy live tree · {recovered:,} recovered counter",
            "Trouble": (
                f"{trouble_zones:,} zones · {self._format_bytes(trouble_bytes)} retained in file findings"
                if trouble_zones else "Waiting for live file findings"
            ),
        }
        for key, value in summary_updates.items():
            self.done_summary_values[key].setText(value)
        self.done_output_path_label.setText(str(recovered_root))
        self._done_output_target = recovered_root if self._path_exists(recovered_root) else self._current_run_dir
        try:
            self.done_open_output_button.setEnabled(
                bool(self._done_output_target and Path(self._done_output_target).is_dir())
            )
        except (OSError, ValueError):
            self.done_open_output_button.setEnabled(False)

    def _refresh_done_live_from_state(self, *, force: bool = False) -> None:
        process = self._process
        if process is None or process.poll() is not None:
            return
        now = time.monotonic()
        if not force and now - self._done_live_last_refresh_at < 2.0:
            return
        self._done_live_last_refresh_at = now
        try:
            run_dir = self._resolve_live_run_directory() or self._current_run_dir
            if run_dir is None:
                return
            recovered_root = run_dir / "recovered"
            if str(recovered_root) != self._done_live_root_path:
                self._current_run_dir = run_dir
                self._reset_done_live_tree(recovered_root)
            state_dir = run_dir / "state"
            self._update_done_live_cards(state_dir, recovered_root)
        except PermissionError as exc:
            now = time.monotonic()
            if now - self._last_state_monitor_permission_warning_at >= 10.0:
                self._last_state_monitor_permission_warning_at = now
                self._append_gui_event(
                    "done_tree_permission",
                    error=exc,
                )
        except (OSError, ValueError) as exc:
            now = time.monotonic()
            if now - self._last_state_monitor_permission_warning_at >= 10.0:
                self._last_state_monitor_permission_warning_at = now
                self._append_gui_event(
                    "done_tree_read_error",
                    error=exc,
                )

    def _refresh_done_from_run(self, return_code: int) -> None:
        if self._stop_requested:
            headline, detail, color = "ABORTED", f"OPERATOR STOP  /  EXIT {return_code}", "#d5a84b"
        elif return_code == 0:
            headline, detail, color = "DONE", "RECOVERY COMPLETED  /  EXIT 0", ACCENT
        else:
            headline, detail, color = "ERROR", f"RECOVERY FAILED  /  EXIT {return_code}", "#e06b75"
        self.done_status_label.setText(headline)
        self.done_status_label.setStyleSheet(
            f"color: {color}; font-family: '{mono_font_family()}'; font-size: 48px; "
            "font-weight: 900; letter-spacing: 3px; border: none;"
        )
        self.done_status_detail.setText(detail)
        run_dir = self._current_run_dir
        state_dir = run_dir / "state" if run_dir else None
        scan = self._read_state_file(state_dir / "scan_state.txt") if state_dir else {}
        stage = self._read_state_file(state_dir / "raw_all_stage.txt") if state_dir else {}
        spool = self._read_state_file(state_dir / "spool_live_stats.txt") if state_dir else {}
        name_state = self._read_state_file(state_dir / "name_salvage_state.txt") if state_dir else {}
        hfs_progress = self._read_state_file(state_dir / "hfsplus_recovery_progress.txt") if state_dir else {}
        hfs_finalize = self._read_state_file(state_dir / "hfsplus_finalize_status.txt") if state_dir else {}
        hypersafe = self._read_state_file(state_dir / "hypersafe_recovery.txt") if state_dir else {}
        hypersafe_source_status = str(
            hypersafe.get("source_status") or ""
        ).strip().lower()
        hypersafe_identity_mismatch = (
            return_code != 0 and hypersafe_source_status == "identity_mismatch"
        )
        if hypersafe_identity_mismatch:
            detail = "WRONG SOURCE REJECTED  /  IMAGE STATE PRESERVED"
            self.done_status_detail.setText(detail)
        selected_scope_done = str(
            stage.get("selected_scope_complete") or ""
        ).strip().lower() in {"1", "true", "yes"}
        full_source_done = str(
            stage.get("full_source_complete") or ""
        ).strip().lower() in {"1", "true", "yes"}
        if return_code == 0 and selected_scope_done and not full_source_done:
            detail = "SELECTED RANGE COMPLETED  /  SOURCE REMAINS"
            self.done_status_detail.setText(detail)

        def metric(*pairs) -> int:
            values = []
            for mapping, key in pairs:
                try:
                    values.append(max(0, int(float(mapping.get(key, 0) or 0))))
                except (TypeError, ValueError):
                    pass
            return max(values, default=0)

        recovered_root = run_dir / "recovered" if run_dir else None
        try:
            (
                disk_files,
                disk_bytes,
                disk_unidentified,
                disk_embedded,
                disk_exact_duplicates,
            ) = self._populate_done_recovered_tree(recovered_root)
        except Exception as exc:
            # Result presentation must never take down a completed recovery.
            disk_files = disk_bytes = disk_unidentified = disk_embedded = 0
            disk_exact_duplicates = 0
            self._done_exact_catalog_duplicate_rows = []
            self._done_exact_catalog_duplicate_paths = set()
            self._done_exact_catalog_duplicate_bytes = 0
            self._done_exact_catalog_duplicate_unresolved = 0
            self._done_exact_catalog_duplicate_embedded = 0
            self.done_recovered_tree.clear()
            self.done_recovered_tree.addTopLevelItem(
                QTreeWidgetItem(["Output browser unavailable", "Recovery output is intact", ""])
            )
            self._append_gui_event("done_browser_error", error=exc)
        raw_embedded = max(
            disk_embedded,
            metric((hfs_finalize, "embedded_outputs")),
        )
        embedded = max(
            0,
            raw_embedded - self._done_exact_catalog_duplicate_embedded,
        )
        disk_unresolved = max(0, disk_unidentified - disk_embedded)
        hypersafe_selected = bool(
            state_dir is not None
            and self._state_path_is_current_run(
                state_dir / "hypersafe_recovery.txt"
            )
            and str(hypersafe.get("strategy") or "").strip()
            == "hypersafe_selected_quick_map_retry"
        )
        hypersafe_selected_complete = 0
        if hypersafe_selected:
            hypersafe_selected_complete = max(
                metric((hypersafe, "final_complete")),
                *(
                    metric((hypersafe, f"{prefix}_recovered"))
                    + metric((hypersafe, f"{prefix}_already_present"))
                    for prefix in ("early", "quick_image", "targeted_retry")
                ),
            )
        recovered = max(
            disk_files,
            metric(
                (spool, "recovered_outputs_current"),
                (stage, "recovered_files"),
            ),
        )
        if hypersafe_selected:
            recovered = max(
                recovered,
                metric(
                    (hypersafe, "recovered_total"),
                    (hypersafe, "final_complete"),
                ),
            )
        if "unresolved_outputs" in hfs_finalize:
            raw_unidentified = metric((hfs_finalize, "unresolved_outputs"))
        else:
            raw_unidentified = max(
                disk_unresolved,
                metric((spool, "unident_outputs_current"), (spool, "files_still_in_unident"),
                       (name_state, "unident_outputs_current"), (name_state, "files_still_in_unident")),
            )
        unidentified = max(
            0,
            raw_unidentified - self._done_exact_catalog_duplicate_unresolved,
        )
        named = max(
            max(0, recovered - raw_unidentified - raw_embedded),
            metric((spool, "named_outputs_current"), (spool, "files_outside_unident"),
                   (stage, "named_files"), (name_state, "named_outputs_current")),
        )
        if hypersafe_selected:
            named = max(named, hypersafe_selected_complete)

        evidence = self._done_evidence_summary(state_dir)
        trouble_zones = evidence["trouble_zones"]
        trouble_bytes = evidence["trouble_bytes"]
        self.done_stat_values["RECOVERED"].setText(f"{recovered:,}")
        self.done_stat_notes["RECOVERED"].setText(
            f"{self._format_bytes(disk_bytes)} present in output tree"
            if disk_bytes else "Output size unavailable from legacy state"
        )
        if hypersafe_selected and recovered and not disk_bytes:
            self.done_stat_notes["RECOVERED"].setText(
                "Hypersafe durable counter · expand the output tree to browse"
            )
        self.done_stat_values["NAMED"].setText(f"{named:,}")
        named_share = (named / recovered * 100.0) if recovered else 0.0
        self.done_stat_notes["NAMED"].setText(f"{named_share:.1f}% of recovered output" if recovered else "No recovered files")
        self.done_stat_values["UNIDENTIFIED"].setText(f"{unidentified:,}")
        if embedded:
            self.done_stat_notes["UNIDENTIFIED"].setText(
                f"retained for review · {embedded:,} embedded contextualized · "
                f"{disk_exact_duplicates:,} exact Catalog duplicate(s) separated"
            )
        elif disk_exact_duplicates:
            self.done_stat_notes["UNIDENTIFIED"].setText(
                f"retained for review · {disk_exact_duplicates:,} exact Catalog "
                "duplicate(s) separated"
            )
        else:
            self.done_stat_notes["UNIDENTIFIED"].setText(
                "retained for review" if unidentified else "none remaining"
            )
        self.done_stat_values["TROUBLE"].setText(f"{trouble_zones:,}")
        self.done_stat_notes["TROUBLE"].setText(f"zones · {self._format_bytes(trouble_bytes)}")

        service_id = self.service_id_combo.currentText().strip() or (run_dir.name if run_dir else "—")
        self.done_service_value.setText(service_id)
        self.done_finished_value.setText("Finished " + datetime.now().strftime("%d %b %Y · %H:%M:%S"))
        elapsed = self._current_run_elapsed()
        self.done_runtime_value.setText(self._format_duration(elapsed))
        self.done_runtime_note.setText("Accumulated across GUI resume sessions" if elapsed else "Runtime was not measured")

        source = str(scan.get("source_path") or (self._selected_source or {}).get("path") or "—")
        destination = str(run_dir or "—")
        mode_code = str(scan.get("scan_mode") or "").lower()
        mode = (
            "Image only"
            if self._image_only_requested()
            else {"all": "Raw File Hunt", "folders": "Tree Recovery",
                  "name": "Name existing carved files"}.get(
                      mode_code, self.mode_combo.currentText()
                  )
        )
        filesystem = self._done_filesystem_summary(state_dir, scan, stage, hfs_progress)
        scope_start = metric((stage, "selected_scope_start_bytes"))
        scope_end = metric((stage, "selected_scope_end_bytes"))
        selected_scope_complete = str(
            stage.get("selected_scope_complete") or ""
        ).strip().lower() in {"1", "true", "yes"}
        full_source_complete = str(
            stage.get("full_source_complete") or ""
        ).strip().lower() in {"1", "true", "yes"}
        if (
            mode_code == "all"
            or self._mode_text_is_raw_hunt(mode)
            or self._mode_text_is_image_only(mode)
        ):
            if scope_end > scope_start and not full_source_complete:
                scope = (
                    f"Selected byte range · {self._format_bytes(scope_start)}–"
                    f"{self._format_bytes(scope_end)} · "
                    f"{'complete' if selected_scope_complete else 'partial'}"
                )
            else:
                scope = "Full source · byte-sequential"
        elif mode_code == "name" or "name existing" in mode.lower():
            scope = "Existing recovered output"
        else:
            scope = self._active_folder_scope_summary(
                "No folder selection recorded"
            )
        source_size = max(0, scope_end - scope_start) or metric(
            (stage, "total_bytes"), (scan, "source_size")
        )
        read_offset = metric(
            (stage, "selected_scope_progress_bytes"),
            (stage, "progress_bytes"),
        )
        if not read_offset:
            read_offset = max(0, metric((scan, "scan_offset")) - scope_start)
        read_text = f"{self._format_bytes(read_offset)} read"
        if source_size:
            read_text += f" of {self._format_bytes(source_size)}"
        speed = str(stage.get("recent_mib_per_sec") or "").strip()
        if speed:
            read_text += f" · {speed} MiB/s recent"
        summary = {
            "Source": source, "Destination": destination, "Mode": mode, "Filesystem": filesystem,
            "Scope": scope, "Filters": self._run_filter_summary(), "Read": read_text,
            "Evidence": f"{evidence['recovery_observations']:,} observations · {self._format_bytes(evidence['recovery_bytes'])} mapped · {recovered:,} files",
            "Trouble": f"{trouble_zones:,} zones · {self._format_bytes(trouble_bytes)} retained in file findings",
        }
        for key, value in summary.items():
            self.done_summary_values[key].setText(value)

        if self._stop_requested:
            note = f"Recovery was stopped by the operator. Exit {return_code}. Partial output and file findings remain available."
        elif hypersafe_identity_mismatch:
            note = (
                "A different source was detected and rejected before imaging resumed. "
                "The existing image and ddrescue map remain safe; reconnect the bound "
                "source and Resume this Service ID."
            )
        elif return_code == 0 and selected_scope_complete and not full_source_complete:
            note = (
                "The selected byte range completed normally; unread source bytes "
                f"remain outside this scope. {unidentified:,} unidentified file(s) "
                "remain for review."
            )
        elif return_code == 0:
            note = f"Recovery completed normally. {trouble_zones:,} trouble zone(s) recorded; {unidentified:,} unidentified file(s) remain for review."
        else:
            note = f"Recovery ended with exit {return_code}. Output may be partial; inspect the event log and retained file findings before restarting or resuming."
        self.done_operator_note.setText(note)
        self.done_output_path_label.setText(str(recovered_root or "—"))
        self._done_output_target = recovered_root if recovered_root and recovered_root.is_dir() else run_dir
        self.done_open_output_button.setEnabled(bool(self._done_output_target and self._done_output_target.is_dir()))
        self._done_summary_text = "\n".join([detail, f"Service ID: {service_id}"] + [f"{key}: {value}" for key, value in summary.items()] + [f"Operator note: {note}"])
        self.done_report_button.setEnabled(True)

    def _done_evidence_summary(self, state_dir: Path | None) -> dict:
        result = {"recovery_observations": 0, "recovery_bytes": 0, "trouble_zones": 0, "trouble_bytes": 0}
        if state_dir is None:
            return result
        recovery = []
        trouble = []
        for row in self._read_tsv_rows(state_dir / "gui_recovery_evidence.tsv"):
            try:
                start, end = int(row.get("start_offset") or 0), int(row.get("end_offset") or 0)
            except (TypeError, ValueError):
                continue
            result["recovery_observations"] += 1
            if str(row.get("geometry") or "").lower() != "point" and end > start:
                recovery.append((start, end))
        for row in self._read_tsv_rows(state_dir / "gui_trouble_evidence.tsv"):
            try:
                start, end = int(row.get("start_offset") or 0), int(row.get("end_offset") or 0)
            except (TypeError, ValueError):
                continue
            if end > start:
                trouble.append((start, end))
        legacy_recovery, legacy_trouble = self._load_legacy_evidence(state_dir)
        if not recovery and result["recovery_observations"] == 0:
            result["recovery_observations"] = len(legacy_recovery)
            recovery.extend(
                (start, end) for start, end, geometry in legacy_recovery
                if geometry == "span" and end > start
            )
        if not trouble:
            trouble.extend((start, end) for start, end, _geometry in legacy_trouble if end > start)
        recovery_union = self._merge_spans(recovery)
        trouble_union = self._merge_spans(trouble)
        result["recovery_bytes"] = sum(end - start for start, end in recovery_union)
        result["trouble_zones"] = len(trouble_union)
        result["trouble_bytes"] = sum(end - start for start, end in trouble_union)
        return result

    @staticmethod
    def _done_recovered_relative_parts(path_text: str, recovered_root: Path) -> list[str]:
        cleaned = str(path_text or "").replace("\\", "/").strip()
        if not cleaned:
            return []
        try:
            candidate = Path(cleaned)
            if candidate.is_absolute():
                try:
                    return [str(part) for part in candidate.relative_to(recovered_root).parts]
                except ValueError:
                    pass
        except (TypeError, ValueError):
            pass
        marker = "/recovered/"
        marker_at = cleaned.casefold().rfind(marker)
        if marker_at >= 0:
            cleaned = cleaned[marker_at + len(marker):]
        return [
            part for part in cleaned.strip("/").split("/")
            if part and part not in {".", ".."}
        ]

    @classmethod
    def _done_recovered_relative_key(cls, path_text: str, recovered_root: Path) -> str:
        return "/".join(cls._done_recovered_relative_parts(path_text, recovered_root)).casefold()

    def _load_done_exact_catalog_duplicates(
        self,
        recovered_root: Path,
    ) -> list[dict]:
        state_dir = recovered_root.parent / "state"
        rows = []
        keys = set()
        total_bytes = 0
        unresolved = 0
        embedded = 0
        for row in self._read_tsv_rows(state_dir / "exact_catalog_duplicates.tsv"):
            duplicate_path = self._state_path_text(row.get("duplicate_path") or "")
            key = self._done_recovered_relative_key(duplicate_path, recovered_root)
            if not key or key in keys:
                continue
            try:
                size = max(0, int(row.get("size") or 0))
            except (TypeError, ValueError):
                size = 0
            parts = self._done_recovered_relative_parts(duplicate_path, recovered_root)
            local_path = recovered_root.joinpath(*parts) if parts else None
            stored = dict(row)
            stored["_relative_key"] = key
            stored["_local_path"] = str(local_path) if local_path is not None else ""
            stored["_size"] = size
            rows.append(stored)
            keys.add(key)
            total_bytes += size
            lowered_parts = {part.casefold() for part in parts}
            if "unidentified" in lowered_parts and "embedded" not in lowered_parts:
                unresolved += 1
            if "embedded" in lowered_parts:
                embedded += 1
        self._done_exact_catalog_duplicate_rows = rows
        self._done_exact_catalog_duplicate_paths = keys
        self._done_exact_catalog_duplicate_bytes = total_bytes
        self._done_exact_catalog_duplicate_unresolved = unresolved
        self._done_exact_catalog_duplicate_embedded = embedded
        self._done_recovered_root = recovered_root
        return rows

    def _done_path_is_exact_catalog_duplicate(
        self,
        path: Path,
        recovered_root: Path,
    ) -> bool:
        key = self._done_recovered_relative_key(str(path), recovered_root)
        return bool(key and key in self._done_exact_catalog_duplicate_paths)

    def _populate_done_recovered_tree(self, recovered_root: Path | None) -> tuple[int, int, int, int, int]:
        tree = self.done_recovered_tree
        self._done_lazy_generation += 1
        self._done_lazy_jobs.clear()
        with self._done_lazy_results_lock:
            self._done_lazy_results.clear()
        self._done_lazy_timer.stop()
        tree.clear()
        if recovered_root is None or not recovered_root.is_dir():
            tree.addTopLevelItem(QTreeWidgetItem(["No recovered output tree", "0 files", "0 B"]))
            return 0, 0, 0, 0, 0

        exact_rows = self._load_done_exact_catalog_duplicates(recovered_root)
        duplicate_status = self._read_state_file(
            recovered_root.parent / "state" / "duplicate_status.txt"
        )

        def status_metric(key: str) -> int:
            try:
                return max(0, int(duplicate_status.get(key, 0) or 0))
            except (TypeError, ValueError):
                return 0

        files = status_metric("files_seen")
        size = status_metric("files_bytes")
        visible_files = max(0, files - len(exact_rows))
        visible_size = max(0, size - self._done_exact_catalog_duplicate_bytes)

        root_item = QTreeWidgetItem([recovered_root.name, "Folder", "—"])
        root_item.setData(0, Qt.ItemDataRole.UserRole, str(recovered_root))
        root_item.setData(0, self._done_loaded_role(), False)
        root_item.addChild(self._done_loading_placeholder())
        tree.addTopLevelItem(root_item)
        if files:
            root_item.setText(1, f"{visible_files:,} regular files")
            root_item.setText(2, self._format_bytes(visible_size))
        else:
            root_item.setText(1, "Expand to browse")
        if exact_rows:
            exact_item = QTreeWidgetItem([
                "EXACT CATALOG DUPLICATES",
                f"{len(exact_rows):,} separated",
                self._format_bytes(self._done_exact_catalog_duplicate_bytes),
            ])
            exact_item.setData(0, self._done_exact_duplicate_role(), True)
            exact_item.setData(0, self._done_loaded_role(), False)
            exact_item.setToolTip(
                0,
                "Full SHA-256 matches retained physically in output but separated "
                "from normal Unidentified review. Both source offsets remain in file findings.",
            )
            exact_item.addChild(self._done_loading_placeholder())
            tree.addTopLevelItem(exact_item)
        return files, size, 0, 0, len(exact_rows)

    @staticmethod
    def _done_loaded_role() -> int:
        return int(getattr(Qt.ItemDataRole.UserRole, "value", Qt.ItemDataRole.UserRole)) + 20

    @staticmethod
    def _done_exact_duplicate_role() -> int:
        return int(getattr(Qt.ItemDataRole.UserRole, "value", Qt.ItemDataRole.UserRole)) + 21

    @staticmethod
    def _done_page_offset_role() -> int:
        return int(getattr(Qt.ItemDataRole.UserRole, "value", Qt.ItemDataRole.UserRole)) + 22

    @staticmethod
    def _done_loading_role() -> int:
        return int(getattr(Qt.ItemDataRole.UserRole, "value", Qt.ItemDataRole.UserRole)) + 23

    @staticmethod
    def _done_loading_placeholder() -> QTreeWidgetItem:
        item = QTreeWidgetItem(["Expand to list contents…", "", ""])
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        return item

    def _queue_done_lazy_directory(
        self,
        item: QTreeWidgetItem,
        directory_text: str,
        *,
        offset: int = 0,
        append: bool = False,
    ) -> None:
        if bool(item.data(0, self._done_loading_role())):
            return
        token = self._done_lazy_next_token
        self._done_lazy_next_token += 1
        generation = self._done_lazy_generation
        page_size = self._done_lazy_page_size
        item.setData(0, self._done_loading_role(), True)
        if not append:
            item.takeChildren()
        loading = QTreeWidgetItem(["Reading this folder…  |", "background", ""])
        loading.setFlags(loading.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        item.addChild(loading)
        self._done_lazy_jobs[token] = (item, loading, append, generation)

        def worker() -> None:
            rows = []
            error = ""
            has_more = False
            next_offset = max(0, int(offset))
            self._done_lazy_scan_lock.acquire()
            try:
                if generation != self._done_lazy_generation:
                    return
                raw_seen = 0
                with os.scandir(directory_text) as entries:
                    for entry in entries:
                        if self._shutdown_started or generation != self._done_lazy_generation:
                            return
                        if raw_seen < offset:
                            raw_seen += 1
                            continue
                        try:
                            is_dir = entry.is_dir(follow_symlinks=False)
                            is_file = entry.is_file(follow_symlinks=False)
                            if not is_dir and not is_file:
                                raw_seen += 1
                                continue
                            if len(rows) >= page_size:
                                has_more = True
                                break
                            size = (
                                max(0, int(entry.stat(follow_symlinks=False).st_size))
                                if is_file else 0
                            )
                            rows.append((entry.name, entry.path, is_dir, size))
                            raw_seen += 1
                            next_offset = raw_seen
                        except (OSError, ValueError):
                            raw_seen += 1
                            next_offset = raw_seen
                            continue
                rows.sort(key=lambda row: (not row[2], row[0].casefold()))
            except (OSError, ValueError) as exc:
                error = str(exc)
            finally:
                self._done_lazy_scan_lock.release()
            if self._shutdown_started or generation != self._done_lazy_generation:
                return
            with self._done_lazy_results_lock:
                self._done_lazy_results.append(
                    (token, generation, directory_text, rows, next_offset, has_more, error)
                )

        self._done_lazy_threads = [
            thread for thread in self._done_lazy_threads if thread.is_alive()
        ]
        thread = threading.Thread(
            target=worker,
            name=f"carv-done-tree-{token}",
            daemon=True,
        )
        self._done_lazy_threads.append(thread)
        thread.start()
        if not self._done_lazy_timer.isActive():
            self._done_lazy_timer.start()

    def _poll_done_lazy_results(self) -> None:
        with self._done_lazy_results_lock:
            results = list(self._done_lazy_results)
            self._done_lazy_results.clear()
        role = self._done_loaded_role()
        for token, generation, directory_text, rows, next_offset, has_more, error in results:
            job = self._done_lazy_jobs.pop(token, None)
            if job is None or generation != self._done_lazy_generation:
                continue
            item, loading, _append, _job_generation = job
            try:
                item.removeChild(loading)
                item.setData(0, self._done_loading_role(), False)
                if error:
                    failed = QTreeWidgetItem([f"Could not list folder: {error}", "", ""])
                    failed.setFlags(failed.flags() & ~Qt.ItemFlag.ItemIsSelectable)
                    item.addChild(failed)
                    continue
                for name, path_text, is_dir, size in rows:
                    path = Path(path_text)
                    if (
                        not is_dir
                        and self._done_recovered_root is not None
                        and self._done_path_is_exact_catalog_duplicate(
                            path, self._done_recovered_root
                        )
                    ):
                        continue
                    if is_dir:
                        child = QTreeWidgetItem([name, "Folder · expand to browse", "—"])
                        child.setData(0, role, False)
                        child.addChild(self._done_loading_placeholder())
                    else:
                        child = QTreeWidgetItem([name, "File", self._format_bytes(size)])
                        child.setData(0, role, True)
                    child.setData(0, Qt.ItemDataRole.UserRole, path_text)
                    child.setToolTip(0, path_text)
                    item.addChild(child)
                if has_more:
                    more = QTreeWidgetItem([
                        f"Load next {self._done_lazy_page_size:,} items…",
                        "Next page",
                        "",
                    ])
                    more.setData(0, Qt.ItemDataRole.UserRole, directory_text)
                    more.setData(0, self._done_page_offset_role(), next_offset)
                    more.setData(0, role, False)
                    more.addChild(self._done_loading_placeholder())
                    item.addChild(more)
                elif item.childCount() == 0:
                    empty = QTreeWidgetItem(["Empty folder", "", ""])
                    empty.setFlags(empty.flags() & ~Qt.ItemFlag.ItemIsSelectable)
                    item.addChild(empty)
                # A collapse is the explicit, low-cost refresh request for the
                # live tree. If it happened while this background scan was in
                # flight, retain the invalid state so the next expansion reads
                # the directory again instead of accepting stale rows.
                item.setData(0, role, bool(item.isExpanded()))
            except RuntimeError:
                # The tree was rebuilt while the worker was reading.  Its
                # generation is already obsolete; there is nothing to show.
                continue
        if not self._done_lazy_jobs and not self._done_lazy_results:
            self._done_lazy_timer.stop()

    def _expand_done_recovered_item(self, item: QTreeWidgetItem) -> None:
        role = self._done_loaded_role()
        page_offset = item.data(0, self._done_page_offset_role())
        if bool(item.data(0, self._done_exact_duplicate_role())):
            offset = max(0, int(page_offset or 0))
            target = item.parent() if page_offset is not None else item
            if target is None:
                return
            if page_offset is not None:
                target.removeChild(item)
            else:
                target.takeChildren()
            end = min(
                len(self._done_exact_catalog_duplicate_rows),
                offset + self._done_lazy_page_size,
            )
            for row in self._done_exact_catalog_duplicate_rows[offset:end]:
                duplicate_path = self._state_path_text(row.get("_local_path") or "")
                canonical_path = self._state_path_text(row.get("canonical_path") or "")
                size = max(0, int(row.get("_size") or 0))
                child = QTreeWidgetItem([
                    Path(duplicate_path).name if duplicate_path else "Exact duplicate",
                    f"Exact copy of {Path(canonical_path).name or 'named Catalog file'}",
                    self._format_bytes(size),
                ])
                if duplicate_path:
                    child.setData(0, Qt.ItemDataRole.UserRole, duplicate_path)
                child.setData(0, role, True)
                child.setToolTip(
                    0,
                    f"Canonical: {canonical_path}\n"
                    f"Catalog offset: {row.get('canonical_offset') or 'unknown'}\n"
                    f"Duplicate offset: {row.get('duplicate_offset') or 'unknown'}\n"
                    f"SHA-256: {row.get('sha256') or 'unknown'}",
                )
                target.addChild(child)
            if end < len(self._done_exact_catalog_duplicate_rows):
                more = QTreeWidgetItem([
                    f"Load next {self._done_lazy_page_size:,} exact duplicates…",
                    "Next page",
                    "",
                ])
                more.setData(0, self._done_exact_duplicate_role(), True)
                more.setData(0, self._done_page_offset_role(), end)
                more.setData(0, role, False)
                more.addChild(self._done_loading_placeholder())
                target.addChild(more)
            elif not self._done_exact_catalog_duplicate_rows:
                target.addChild(QTreeWidgetItem(["No exact Catalog duplicates", "", ""]))
            target.setData(0, role, True)
            return
        if page_offset is not None:
            parent = item.parent()
            directory_text = self._state_path_text(
                item.data(0, Qt.ItemDataRole.UserRole) or ""
            )
            if parent is not None and directory_text:
                parent.removeChild(item)
                self._queue_done_lazy_directory(
                    parent,
                    directory_text,
                    offset=max(0, int(page_offset)),
                    append=True,
                )
            return
        if bool(item.data(0, role)):
            return
        path_text = self._state_path_text(item.data(0, Qt.ItemDataRole.UserRole) or "")
        if path_text:
            self._queue_done_lazy_directory(item, path_text)

    def _invalidate_done_recovered_item(self, item: QTreeWidgetItem) -> None:
        """Forget one real directory page so its next expansion re-reads it."""
        if bool(item.data(0, self._done_exact_duplicate_role())):
            return
        if item.data(0, self._done_page_offset_role()) is not None:
            return
        path_text = self._state_path_text(
            item.data(0, Qt.ItemDataRole.UserRole) or ""
        )
        if path_text:
            item.setData(0, self._done_loaded_role(), False)

    def _open_done_output_folder(self) -> None:
        target = getattr(self, "_done_output_target", None)
        try:
            if not target or not Path(target).is_dir():
                return
        except ValueError:
            return
        command = ["open", str(target)] if sys.platform == "darwin" else ["xdg-open", str(target)]
        try:
            subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as exc:
            QMessageBox.warning(self, "Open output folder", f"Could not open the output folder:\n\n{exc}")

    def _open_done_recovered_item(self, item: QTreeWidgetItem, _column: int = 0) -> None:
        path_text = self._state_path_text(item.data(0, Qt.ItemDataRole.UserRole) or "")
        target = Path(path_text) if path_text else None
        try:
            if target is None or not target.is_file():
                return
        except ValueError:
            return
        if sys.platform == "darwin":
            command = ["open", str(target)]
        elif sys.platform.startswith("linux"):
            command = ["xdg-open", str(target)]
        else:
            QMessageBox.warning(
                self,
                "Open recovered file",
                f"Opening recovered files is not implemented for {sys.platform}.",
            )
            return
        try:
            subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            QMessageBox.warning(
                self,
                "Open recovered file",
                f"Could not open the recovered file:\n\n{target}\n\n{exc}",
            )

    def _copy_done_summary(self) -> None:
        text = getattr(self, "_done_summary_text", "").strip()
        if text:
            QApplication.clipboard().setText(text)
            self.done_report_button.setText("SUMMARY COPIED")
            QTimer.singleShot(1800, lambda: self.done_report_button.setText("COPY RUN SUMMARY"))

    def _resolve_live_run_directory(self) -> Path | None:
        current = self._current_run_dir
        if current is None:
            return None
        service_id = self.service_id_combo.currentText().strip() if hasattr(self, "service_id_combo") else ""
        candidates = [current]
        if service_id:
            candidates.append(current / service_id)
            if self._selected_output:
                output = Path(self._selected_output).expanduser()
                # --out is normally the destination root and carv creates the
                # service-id directory below it.  Only consider the root itself
                # a run directory when it is already named after the service id;
                # otherwise an unrelated root-level state/ directory can win.
                if output.name == service_id:
                    candidates.append(output)
                    candidates.append(output / service_id)
                else:
                    candidates.append(output / service_id)
        unique = []
        seen = set()
        for candidate in candidates:
            key = str(candidate)
            if key not in seen:
                seen.add(key)
                unique.append(candidate)
        artifact_names = (
            "scan_state.txt", "raw_all_stage.txt", "spool_live_stats.txt",
            "hfsplus_recovery_progress.txt",
            "hfsplus_recovery_failures.tsv",
            "gui_passes.tsv", "gui_read_coverage.tsv", "gui_recovery_evidence.tsv",
            "recovered_outputs.tsv", "runtime_events.log",
        )

        def score(candidate: Path) -> tuple[int, int, int]:
            state = candidate / "state"
            present = 0
            bytes_present = 0
            newest_mtime = 0
            for name in artifact_names:
                stat = self._path_stat(state / name)
                if stat is None:
                    continue
                present += 1
                bytes_present += stat.st_size
                newest_mtime = max(newest_mtime, stat.st_mtime_ns)
            # The active run is the one carv has touched most recently.  File
            # count/size only break ties; old bulky state must not beat live data.
            return newest_mtime, present, bytes_present

        best = max(unique, key=score)
        if best != current and score(best) > score(current):
            self._current_run_dir = best
            self._set_run_context_destination(str(best))
            self._evidence_cache = {"stamp": None, "data": None}
            self._tsv_rows_cache = {}
            self._last_evidence_refresh_at = 0.0
            self._activity_known_error_segments = []
            self._activity_known_skipped_segments = []
        return self._current_run_dir

    def _develop_run_time_category(
        self,
        *,
        phase: str,
        stage: dict,
        activity: dict,
    ) -> str:
        stage_name = str(stage.get("stage") or "").strip().casefold()
        activity_text = " ".join((
            str(phase or ""),
            str(stage.get("activity") or ""),
            str(stage.get("detail") or ""),
            str(activity.get("scan.activity") or ""),
            str(activity.get("scan.background_activity") or ""),
        )).casefold()

        def metric(*keys: str) -> float:
            for key in keys:
                try:
                    value = float(activity.get(key, 0) or 0)
                except (TypeError, ValueError):
                    continue
                if value > 0:
                    return value
            return 0.0

        queue_count = metric(
            "async.queue_count", "write_queue.count", "recovery.queue_count"
        )
        queue_capacity = metric(
            "async.queue_capacity", "write_queue.capacity", "recovery.queue_capacity"
        )
        outstanding = metric(
            "async.outstanding_bytes", "write_queue.bytes", "recovery.outstanding_bytes"
        )
        output_words = (
            "output wait", "queue full", "backpressure", "writing output",
            "flushing output", "fsync", "rename output",
        )
        if (
            any(word in activity_text for word in output_words)
            or (queue_capacity > 0 and queue_count >= queue_capacity * 0.90)
            or (outstanding > 0 and "stalled" in activity_text)
        ):
            return "output_wait"

        validation_words = (
            "validating", "validation", "validator", "claim audit",
            "claim-audit", "jpeg repair", "block-bridge", "revisiting",
        )
        if any(word in activity_text for word in validation_words):
            return "validation"

        metadata_stages = {
            "primary_metadata_bootstrap", "primary_mft_bootstrap", "mft_index",
            "metadata_index", "post_scan_reconcile", "recover_missed",
            "auto_name_handoff", "name_salvage",
        }
        metadata_words = (
            "catalog", "metadata", "mft", "shadow index", "extent index",
            "reconcil", "name salvage", "naming", "parent chain",
        )
        if stage_name in metadata_stages or any(
            word in activity_text for word in metadata_words
        ):
            return "metadata"

        other_stages = {
            "startup", "resume_loading", "post_scan_finalize", "completed",
            "done", "selected_scope_completed",
        }
        other_words = (
            "starting", "preparing", "resume", "restart", "finalizing",
            "cleaning", "supervisor", "waiting for state",
        )
        if stage_name in other_stages or any(
            word in activity_text for word in other_words
        ):
            return "restart_other"
        return "source"

    def _sample_develop_run_time(
        self,
        *,
        phase: str,
        stage: dict,
        activity: dict,
    ) -> None:
        now = time.monotonic()
        last = float(self._develop_time_last_sample_at or 0.0)
        self._develop_time_last_sample_at = now
        if last <= 0.0:
            return
        elapsed = max(0.0, min(2.0, now - last))
        if elapsed <= 0.0:
            return
        category = self._develop_run_time_category(
            phase=phase,
            stage=stage,
            activity=activity,
        )
        self._develop_time_buckets[category] += elapsed
        total = sum(self._develop_time_buckets.values())
        if total <= 0.0 or not hasattr(self, "run_develop_time_row"):
            return
        raw_values = {
            key: (self._develop_time_buckets[key] / total * 100.0)
            for key in self._develop_time_buckets
        }
        values = {key: int(value) for key, value in raw_values.items()}
        missing = 100 - sum(values.values())
        for key in sorted(
            values,
            key=lambda name: raw_values[name] - values[name],
            reverse=True,
        )[:missing]:
            values[key] += 1
        self.run_develop_time_row.setText(
            "DEVELOP TIME · "
            f"Source {values['source']} % · "
            f"validation {values['validation']} % · "
            f"output wait {values['output_wait']} % · "
            f"metadata {values['metadata']} % · "
            f"restart/other {values['restart_other']} %"
        )

    def _update_run_from_state(self, force_evidence: bool = False) -> None:
        if self._current_run_dir is None:
            return
        run_dir = self._resolve_live_run_directory()
        if run_dir is None:
            return
        state_dir = run_dir / "state"
        scan = self._read_state_file(state_dir / "scan_state.txt")
        stage = self._read_state_file(state_dir / "raw_all_stage.txt")
        spool = self._read_state_file(state_dir / "spool_live_stats.txt")
        activity = self._read_state_file(state_dir / "thread_activity.txt")
        hfs_progress = self._read_state_file(
            state_dir / "hfsplus_recovery_progress.txt"
        )
        hfs_catalog = self._read_state_file(
            state_dir / "hfsplus_catalog_progress.txt"
        )
        hfs_shadow = self._read_state_file(
            state_dir / "metadata" / "shadow_status.txt"
        )
        hfs_extent = self._read_state_file(
            state_dir / "metadata" / "sequential_extent_measurement.txt"
        )
        deferred_plan = self._read_state_file(
            state_dir / "deferred_plan_state.txt"
        )
        coverage_retry = self._read_state_file(
            state_dir / "coverage_gap_retry_state.txt"
        )
        ddrescue_supervisor = self._read_state_file(
            state_dir / "ddrescue_supervisor.txt"
        )
        hypersafe = self._read_state_file(
            state_dir / "hypersafe_recovery.txt"
        )
        hypersafe_identity = self._read_state_file(
            state_dir / "hypersafe_identity.txt"
        )
        folder_scope_resolution = self._read_state_file(
            state_dir / "folder_scope_resolution.txt"
        )
        self._set_live_monitor_status("reading state")

        def number(values, key, default=0):
            try:
                return int(float(values.get(key, default) or default))
            except (TypeError, ValueError):
                return default

        hfs_state_path = state_dir / "hfsplus_recovery_progress.txt"
        try:
            hfs_state_is_current = (
                not self._run_started_wall_time
                or hfs_state_path.stat().st_mtime >= self._run_started_wall_time - 1.0
            )
        except OSError:
            hfs_state_is_current = False
        stage_state_path = state_dir / "raw_all_stage.txt"
        hfs_state_stat = self._path_stat(hfs_state_path)
        stage_state_stat = self._path_stat(stage_state_path)
        stage_state_name = str(stage.get("stage") or "").strip().lower()
        raw_stage_has_newer_authority = bool(
            stage_state_stat is not None
            and hfs_state_stat is not None
            and stage_state_stat.st_mtime > hfs_state_stat.st_mtime + 1.0
            and stage_state_name not in {"", "folders", "metadata_recovery"}
        )
        hfs_state_valid = (
            hfs_state_is_current
            and not raw_stage_has_newer_authority
            and str(hfs_progress.get("backend") or "").strip().lower() == "hfsplus"
        )
        if hfs_state_valid:
            self._run_progress_authority = "hfsplus"
            self._hfs_progress_cache = dict(hfs_progress)
        elif raw_stage_has_newer_authority:
            self._run_progress_authority = "raw"
        elif self._run_progress_authority == "hfsplus" and self._hfs_progress_cache:
            hfs_progress = dict(self._hfs_progress_cache)
        hfs_active = self._run_progress_authority == "hfsplus"

        live = self._live_metrics
        process_live = self._process is not None and self._process.poll() is None

        def state_file_is_current(path: Path) -> bool:
            return self._state_path_is_current_run(path)

        hypersafe_active = bool(
            state_file_is_current(state_dir / "hypersafe_recovery.txt")
            and str(hypersafe.get("backend") or "").strip().lower() == "ntfs"
            and str(hypersafe.get("strategy") or "").strip().startswith("hypersafe_")
        )
        hypersafe_source_status = str(
            hypersafe.get("source_status") or "waiting_for_source"
        ).strip().lower()
        hypersafe_display_detail = str(
            hypersafe.get("detail") or "Hypersafe is preparing the image"
        ).strip()
        bound_source_path = str(
            hypersafe_identity.get("source_path")
            or hypersafe.get("source_path")
            or ""
        ).strip()
        if (
            hypersafe_active
            and process_live
            and str(hypersafe.get("workflow_status") or "").strip().lower()
            not in {"completed", "failed", "interrupted"}
            and hypersafe_source_status == "connected"
            and bound_source_path.startswith("/dev/")
            and not Path(bound_source_path).exists()
        ):
            # ddrescue may need up to its no-progress timeout to report a
            # vanished device.  The GUI can truthfully show the missing path
            # immediately without changing the durable recovery state.
            hypersafe_source_status = "waiting_for_source"
        source_detail_overrides = {
            "waiting_for_source": (
                hypersafe_display_detail
                if str(hypersafe.get("source_path") or "").strip()
                == WAIT_FOR_NEW_SOURCE_TOKEN
                else "Source unavailable; image and mapfile are saved while Carv waits "
                "for the same disk"
            ),
            "verifying_source": (
                "A source appeared; verifying its identity before imaging resumes"
            ),
            "identity_unavailable": (
                "Source detected, but identity evidence is temporarily unreadable; "
                "Carv is waiting without rejecting the disk"
            ),
            "identity_mismatch": (
                "WRONG SOURCE REJECTED · image and mapfile remain unchanged"
            ),
        }
        hypersafe_display_detail = source_detail_overrides.get(
            hypersafe_source_status,
            hypersafe_display_detail,
        )
        if hypersafe_active and hasattr(self, "source_panel"):
            source_labels = {
                "waiting_for_source": "WAITING FOR SOURCE",
                "binding_source": "BINDING SOURCE",
                "verifying_source": "VERIFYING SOURCE",
                "identity_unavailable": "WAITING FOR READABLE IDENTITY",
                "connected": "BOUND · CONNECTED",
                "identity_mismatch": "WRONG SOURCE",
            }
            self.source_panel.source_meta.setText(
                source_labels.get(
                    hypersafe_source_status,
                    hypersafe_source_status.upper().replace("_", " "),
                )
            )
            source_color = (
                "#ff6975" if hypersafe_source_status == "identity_mismatch"
                else WARNING if hypersafe_source_status in {
                    "waiting_for_source", "identity_unavailable"
                }
                else ACCENT
            )
            self.source_panel.source_meta.setStyleSheet(
                f"color: {source_color}; background: transparent; "
                f"font-family: '{mono_font_family()}'; font-size: 10px; "
                "font-weight: 700; letter-spacing: 0.8px;"
            )

        scan_current = state_file_is_current(state_dir / "scan_state.txt")
        activity_current = state_file_is_current(state_dir / "thread_activity.txt")
        stage_current = state_file_is_current(state_dir / "raw_all_stage.txt")
        catalog_current = state_file_is_current(
            state_dir / "hfsplus_catalog_progress.txt"
        )
        current_scan = scan if scan_current else {}
        current_stage = stage if stage_current else {}
        current_activity = activity if activity_current else {}
        backend_id = str(
            current_stage.get("fs_backend")
            or current_activity.get("scan.fs_backend")
            or hfs_catalog.get("backend")
            or ""
        ).strip().lower()
        raw_hfs = backend_id == "hfsplus" and not hfs_active

        scope_start = number(current_stage, "selected_scope_start_bytes")
        scope_end = number(current_stage, "selected_scope_end_bytes")
        scoped_total = max(0, scope_end - scope_start)
        if process_live and activity_current:
            total = scoped_total or number(current_activity, "scan.total_bytes")
            activity_progress = number(current_activity, "scan.progress_bytes")
            activity_absolute = number(current_activity, "scan.offset")
            if scoped_total > 0:
                offset = (
                    activity_progress
                    if activity_progress <= scoped_total
                    else max(0, activity_absolute - scope_start)
                )
            else:
                offset = activity_progress or activity_absolute
        elif stage_current and scoped_total > 0:
            total = scoped_total
            offset = number(current_stage, "selected_scope_progress_bytes")
        else:
            total = (
                scoped_total
                or number(current_activity, "scan.total_bytes")
                or number(current_stage, "total_bytes")
                or int(live.get("total") or 0)
                or number(current_scan, "source_size")
                or int((self._selected_source or {}).get("size_bytes") or 0)
            )
            absolute_offset = max(
                number(current_scan, "scan_offset"),
                number(current_activity, "scan.offset"),
                int(live.get("offset") or 0),
            )
            offset = max(0, absolute_offset - scope_start) if scope_start else absolute_offset
        if total > 0:
            offset = min(offset, total)
        evidence_total = (
            number(current_stage, "source_size_bytes")
            or number(current_scan, "source_size")
            or int((self._selected_source or {}).get("size_bytes") or 0)
            or total
        )

        selected_scope_complete = str(
            current_stage.get("selected_scope_complete") or ""
        ).strip().lower() in {"1", "true", "yes"}
        full_source_complete = str(
            current_stage.get("full_source_complete") or ""
        ).strip().lower() in {"1", "true", "yes"}
        scan_completed = str(current_scan.get("completed") or "").strip() == "1"
        stage_name = str(current_stage.get("stage") or "").strip().lower()
        post_scan_stage_names = {
            "retry_hotspots", "coverage_gap_retry", "post_scan_reconcile",
            "recover_missed", "post_scan_finalize", "auto_name_handoff",
        }
        stage_completed = stage_name in {
            "completed", "done", "selected_scope_completed",
        }
        state_percent = (offset / total * 100.0) if total > 0 else 0.0
        try:
            live_percent = float(live.get("percent") or 0.0)
        except (TypeError, ValueError):
            live_percent = 0.0
        # Terminal progress is sampled periodically and may be one refresh
        # behind when a fast run exits. Durable state is authoritative.
        percent = 100.0 if (
            scan_completed or selected_scope_complete or stage_completed
        ) else max(state_percent, live_percent if not (activity_current or scoped_total) else 0.0)
        percent = max(0.0, min(100.0, percent))
        if not hfs_active:
            display_percent = percent
            catalog_phase = str(hfs_catalog.get("phase") or "").strip().lower()
            try:
                catalog_percent = max(
                    0.0,
                    min(100.0, float(hfs_catalog.get("leaf_progress_percent") or 0.0)),
                )
            except (TypeError, ValueError):
                catalog_percent = 0.0
            primary_started = offset > 0 or (
                activity_current and number(current_activity, "scan.total_bytes_read") > 0
            )
            if raw_hfs and catalog_current and not primary_started:
                # Preparation is deliberately a small, visible portion of the
                # whole run.  It advances with real Catalog leaf progress and
                # cannot jump backwards when the primary byte scan begins.
                display_percent = min(1.5, catalog_percent * 0.015)
                if catalog_phase == "complete":
                    display_percent = 1.5
            elif raw_hfs and not (selected_scope_complete or stage_completed):
                display_percent = 2.0 + (percent * 0.97)
                display_percent = min(99.0, display_percent)
            display_percent = max(self._last_run_display_percent, display_percent)
            self._last_run_display_percent = display_percent
            self.run_preview_progress.setRange(0, 1000)
            self.run_percent_value.setText(f"{display_percent:.1f}%")
            self.run_preview_progress.setValue(
                max(0, min(1000, round(display_percent * 10)))
            )
            self.run_cursor_value.setText(
                f"{self._format_bytes(offset)} / "
                f"{self._format_bytes(total) if total else '—'}"
            )
        elapsed = self._current_run_elapsed()
        self.run_elapsed_value.setText(f"Elapsed {self._format_duration(elapsed)}")
        speed = 0.0
        live_speed_text = str(live.get("speed") or "").strip()
        try:
            speed_text = str(stage.get("recent_mib_per_sec") or "0")
            if live_speed_text and "mib/s" in live_speed_text.lower():
                speed_text = live_speed_text
            speed_match = re.search(r"\d+(?:\.\d+)?", speed_text)
            speed = float(speed_match.group(0)) if speed_match else 0.0
        except (TypeError, ValueError):
            speed = 0.0
        if not hfs_active:
            if scan_completed or selected_scope_complete or stage_completed:
                self.run_eta_value.setText("COMPLETE")
            elif live.get("eta"):
                self.run_eta_value.setText(str(live["eta"]))
            elif speed > 0 and total > offset:
                eta_seconds = (total - offset) / (speed * 1024 * 1024)
                self.run_eta_value.setText(self._format_duration(eta_seconds))
            else:
                self.run_eta_value.setText("CALCULATING")
        stage_activity = str(current_stage.get("activity") or "").strip()
        stage_detail = str(current_stage.get("detail") or "").strip()
        if process_live and stage_current and stage_name in (
            {"startup", "resume_loading"} | post_scan_stage_names
        ):
            phase = stage_activity or stage_detail or stage_name
        else:
            phase = live.get("phase") or stage_activity or stage_detail or stage.get("stage") or scan.get("scan_mode") or "Starting"
        if raw_hfs and catalog_current and not primary_started:
            catalog_phase = str(hfs_catalog.get("phase") or "").strip().lower()
            catalog_entries = number(hfs_catalog, "entries_parsed")
            catalog_total = number(hfs_catalog, "leaf_records_total")
            catalog_seen = number(hfs_catalog, "leaf_records_visited")
            if catalog_phase != "complete":
                phase = (
                    f"Reading HFS+ Catalog · {catalog_percent:.1f}% · "
                    f"{catalog_entries:,} entries"
                )
                self.run_cursor_value.setText(
                    f"Catalog records {catalog_seen:,} / {catalog_total:,}"
                    if catalog_total else "Reading HFS+ Catalog"
                )
            elif str(hfs_shadow.get("status") or "").strip().lower() != "ready":
                phase = "Building and verifying compact HFS+ metadata index"
                self.run_cursor_value.setText(
                    f"Catalog ready · {catalog_entries:,} entries"
                )
        coverage_status = str(coverage_retry.get("status") or "").strip().lower()
        coverage_state_current = state_file_is_current(
            state_dir / "coverage_gap_retry_state.txt"
        )
        ddrescue_supervisor_current = state_file_is_current(
            state_dir / "ddrescue_supervisor.txt"
        )
        coverage_retry_active = bool(
            process_live
            and stage_name in {"retry_hotspots", "coverage_gap_retry"}
            and coverage_state_current
            and coverage_status in {"planned", "scanning", "chunk_complete", "chunk_failed"}
        )
        post_scan_notice_visible = bool(
            not hfs_active
            and process_live
            and (
                scan_completed
                or selected_scope_complete
                or stage_name in post_scan_stage_names
            )
            and stage_name not in {"completed", "done", "selected_scope_completed"}
        )
        if hasattr(self, "run_post_scan_notice"):
            self.run_post_scan_notice.setVisible(post_scan_notice_visible)
        if coverage_retry_active:
            gap_index = number(coverage_retry, "gap_index")
            gap_count = number(coverage_retry, "gap_count")
            attempt_index = number(coverage_retry, "attempt_index")
            attempted_bytes = number(coverage_retry, "attempted_bytes")
            retry_budget = number(coverage_retry, "retry_budget_bytes")
            validator = stage_activity if stage_activity.startswith("validating ") else "reading source bytes"
            phase = (
                f"Coverage-gap reread · gap {gap_index:,}/{gap_count:,} · "
                f"chunk {attempt_index:,} · {validator}"
            )
            self.run_metric_values["STALLED"].setText("bounded retry")
            self.run_eta_value.setText("RETRY BUDGET")
            self.run_cursor_value.setText(
                f"Source read complete · retry {self._format_bytes(attempted_bytes)} / "
                f"{self._format_bytes(retry_budget)} budget"
            )
        self.run_metric_values["PHASE"].setText(str(phase))
        if (
            not hfs_active
            and process_live
            and (
                scan_completed
                or selected_scope_complete
                or stage_name in post_scan_stage_names
            )
            and stage_name not in {"completed", "done", "selected_scope_completed"}
        ):
            if coverage_status not in {"planned", "scanning", "chunk_complete", "chunk_failed"}:
                self.run_eta_value.setText("POST-SCAN WORK")
                self.run_cursor_value.setText(
                    f"Source read complete · {self._format_bytes(total)}"
                    if total else "Source read complete"
                )
        if coverage_retry_active and stage_activity.startswith("validating "):
            self.run_metric_values["READ SPEED"].setText(
                "CPU validation · source cursor paused"
            )
        else:
            self.run_metric_values["READ SPEED"].setText(
                live_speed_text or (f"{speed:.1f} MiB/s" if speed > 0 else "measuring")
            )
        if not coverage_retry_active:
            self.run_metric_values["STALLED"].setText(
                str(live.get("stalled")) if live.get("stalled") else
                self._format_duration(number(spool, "scan_stalled_seconds"))
            )
        recovered = number(spool, "recovered_outputs_current") or number(stage, "recovered_files") or int(live.get("carved") or 0)
        if raw_hfs:
            recovered = max(
                recovered,
                number(hfs_extent, "assembly_files_completed"),
            )
        named = number(spool, "named_outputs_current") or int(live.get("named") or 0)
        unidentified = number(spool, "unident_outputs_current") or int(live.get("unnamed") or 0)
        total_files = max(
            number(spool, "total_files"),
            number(spool, "files_total"),
            number(stage, "total_files"),
            named + unidentified,
            recovered,
        )
        if raw_hfs:
            activity = dict(activity)
            activity["scan.activity"] = str(phase)
            activity["recovery.jobs_completed"] = str(recovered)
            activity["recovery.bytes_written"] = str(
                number(hfs_extent, "assembly_bytes_written")
            )
            planned = number(deferred_plan, "planned_entries")
            suppressed = number(deferred_plan, "metadata_owned_suppressed")
            if planned or suppressed:
                activity["scan.background_activity"] = (
                    f"Deferred plan {planned:,} ranges · "
                    f"{suppressed:,} metadata-owned suppressed"
                )
        operator_total = total
        durable_state_is_current = False
        for durable_name in ("scan_state.txt", "raw_all_stage.txt"):
            try:
                if (
                    not self._run_started_wall_time
                    or (state_dir / durable_name).stat().st_mtime
                    >= self._run_started_wall_time - 1.0
                ):
                    durable_state_is_current = True
                    break
            except OSError:
                continue
        evidence_offset = (scope_start + offset) if durable_state_is_current else 0
        if hfs_active:
            if hasattr(self, "run_post_scan_notice"):
                self.run_post_scan_notice.setVisible(False)
            plan_ready = str(hfs_progress.get("plan_ready") or "").strip() == "1"
            hfs_phase = str(hfs_progress.get("phase") or "starting").strip()
            hfs_activity = str(
                hfs_progress.get("activity") or "Starting HFS+ metadata recovery"
            ).strip()
            hfs_bytes = number(hfs_progress, "bytes_written")
            hfs_bytes_total = number(hfs_progress, "bytes_total")
            hfs_files = number(hfs_progress, "files_completed")
            hfs_files_total = number(hfs_progress, "files_total")
            operator_total = hfs_bytes_total
            recovered = hfs_files
            total_files = hfs_files_total
            phase = hfs_activity

            if plan_ready:
                try:
                    hfs_percent = float(
                        hfs_progress.get("progress_percent") or 0.0
                    )
                except (TypeError, ValueError):
                    hfs_percent = 0.0
                hfs_percent = max(0.0, min(100.0, hfs_percent))
                hfs_percent = max(self._last_hfs_progress_percent, hfs_percent)
                self._last_hfs_progress_percent = hfs_percent
                self.run_preview_progress.setRange(0, 1000)
                self.run_preview_progress.setValue(round(hfs_percent * 10))
                self.run_percent_value.setText(f"{hfs_percent:.1f}%")
                self.run_cursor_value.setText(
                    f"{self._format_bytes(hfs_bytes)} / "
                    f"{self._format_bytes(hfs_bytes_total) if hfs_bytes_total else '—'} selected"
                )
                eta_seconds = number(hfs_progress, "eta_seconds", -1)
                if hfs_phase in {"complete", "complete_with_errors"}:
                    self.run_eta_value.setText("COMPLETE")
                elif eta_seconds >= 0:
                    self.run_eta_value.setText(self._format_duration(eta_seconds))
                else:
                    self.run_eta_value.setText("CALCULATING")
            else:
                self.run_preview_progress.setRange(0, 0)
                self.run_percent_value.setText("PLANNING")
                planned = number(hfs_progress, "planning_entries_processed")
                planned_total = number(hfs_progress, "planning_entries_total")
                self.run_cursor_value.setText(
                    f"Catalog {planned:,} / {planned_total:,} entries"
                    if planned_total > 0 else "Reading HFS+ metadata"
                )
                self.run_eta_value.setText("ESTIMATING")

            try:
                hfs_speed = float(
                    hfs_progress.get("recent_mib_per_sec") or 0.0
                )
            except (TypeError, ValueError):
                hfs_speed = 0.0
            self.run_metric_values["PHASE"].setText(hfs_activity)
            self.run_metric_values["READ SPEED"].setText(
                f"{hfs_speed:.1f} MiB/s" if hfs_speed > 0 else "measuring"
            )
            self.run_metric_values["STALLED"].setText(
                "finalizing" if hfs_phase == "finalizing" else "active"
            )
            activity = dict(activity)
            activity.update({
                "mode": "folders",
                "scan.activity": hfs_activity,
                "recovery.jobs_completed": str(hfs_files),
                "recovery.bytes_written": str(hfs_bytes),
                "recovery.files_incomplete": str(
                    number(hfs_progress, "files_incomplete")
                ),
                "recovery.files_failed": str(number(hfs_progress, "files_failed")),
                "recovery.current_path": str(hfs_progress.get("current_path") or ""),
            })
        elif hypersafe_active:
            hypersafe_selected = str(
                hypersafe.get("strategy") or ""
            ).strip() == "hypersafe_selected_quick_map_retry"
            hypersafe_stage = str(
                hypersafe.get("stage") or "armed_waiting_for_source"
            ).strip()
            hypersafe_detail = hypersafe_display_detail
            source_total = number(hypersafe, "source_size_bytes")
            rescued_bytes = number(hypersafe, "map_rescued_bytes")
            selected_files = number(hypersafe, "selected_files")
            requested_folders = decode_folder_scope_paths(
                str(hypersafe.get("root_scope_csv") or "")
            )
            saved_query_folders = decode_folder_scope_paths(
                str(folder_scope_resolution.get("query") or "")
            )
            query_folders = requested_folders or saved_query_folders
            normalized_requested = [
                item.strip().casefold() for item in requested_folders
            ]
            normalized_saved = [
                item.strip().casefold() for item in saved_query_folders
            ]
            folder_resolution_ready = bool(
                state_file_is_current(state_dir / "folder_scope_resolution.txt")
                and normalized_saved
                and (
                    not normalized_requested
                    or normalized_saved == normalized_requested
                )
            )
            matched_folders = (
                decode_folder_scope_paths(
                    str(folder_scope_resolution.get("resolved") or "")
                )
                if folder_resolution_ready
                else []
            )

            def result_counts(prefix: str) -> tuple[int, int, int, int]:
                return (
                    number(hypersafe, f"{prefix}_recovered"),
                    number(hypersafe, f"{prefix}_already_present"),
                    number(hypersafe, f"{prefix}_waiting"),
                    number(hypersafe, f"{prefix}_failed"),
                )

            result_prefix = "early"
            for candidate in ("quick_image", "targeted_retry", "final"):
                candidate_counts = result_counts(candidate)
                candidate_accounted = sum(candidate_counts)
                if candidate == "final":
                    candidate_accounted += number(
                        hypersafe, "final_unaccounted"
                    )
                if candidate_accounted > 0:
                    result_prefix = candidate
            if hypersafe_stage == "completed":
                result_prefix = "final"
            priority_recovered = number(
                hypersafe, f"{result_prefix}_recovered"
            )
            priority_already = number(
                hypersafe, f"{result_prefix}_already_present"
            )
            priority_waiting = number(
                hypersafe, f"{result_prefix}_waiting"
            )
            priority_failed = number(
                hypersafe, f"{result_prefix}_failed"
            )
            priority_output_folders = number(
                hypersafe,
                f"{result_prefix}_folders_with_complete_files",
            )
            priority_complete = priority_recovered + priority_already
            priority_unaccounted = (
                max(
                    number(hypersafe, "final_unaccounted"),
                    selected_files
                    - priority_complete
                    - priority_waiting
                    - priority_failed,
                    0,
                )
                if result_prefix == "final"
                else max(
                    0,
                    selected_files
                    - priority_complete
                    - priority_waiting
                    - priority_failed,
                )
            )
            operator_total = source_total
            offset = rescued_bytes
            phase = hypersafe_detail
            if source_total > 0:
                image_percent = max(
                    0.0,
                    min(100.0, rescued_bytes / source_total * 100.0),
                )
                if str(hypersafe.get("image_complete") or "") == "1":
                    image_percent = 100.0
                self.run_preview_progress.setRange(0, 1000)
                self.run_preview_progress.setValue(round(image_percent * 10))
                self.run_percent_value.setText(f"{image_percent:.1f}%")
                self.run_cursor_value.setText(
                    f"{self._format_bytes(rescued_bytes)} / "
                    f"{self._format_bytes(source_total)} imaged"
                )
            else:
                self.run_preview_progress.setRange(0, 0)
                self.run_percent_value.setText("ARMED")
                self.run_cursor_value.setText("Waiting for the selected source path")
            self.run_eta_value.setText(
                "WAITING" if hypersafe_source_status in {
                    "waiting_for_source", "identity_unavailable"
                }
                else "VERIFYING" if hypersafe_source_status == "verifying_source"
                else "REJECTED" if hypersafe_source_status == "identity_mismatch"
                else "COMPLETE" if hypersafe_stage == "completed"
                else "CALCULATING"
            )
            self.run_metric_values["PHASE"].setText(hypersafe_detail)
            self.run_metric_values["READ SPEED"].setText(
                str(live.get("speed") or "measuring")
            )
            self.run_metric_values["STALLED"].setText(
                "waiting for source"
                if hypersafe_source_status == "waiting_for_source"
                else "waiting for readable identity"
                if hypersafe_source_status == "identity_unavailable"
                else "verifying source"
                if hypersafe_source_status == "verifying_source"
                else "wrong source rejected"
                if hypersafe_source_status == "identity_mismatch"
                else "active"
            )
            activity = {
                "mode": "image",
                "scan.activity": hypersafe_detail,
                "activity.hypersafe": {
                    "state": dict(hypersafe),
                    "detail": hypersafe_detail,
                    "source_status": hypersafe_source_status,
                    "selected": hypersafe_selected,
                    "folder_resolution_ready": folder_resolution_ready,
                    "query_count": len(query_folders),
                    "matched_count": len(matched_folders),
                    "priority_complete": priority_complete,
                    "priority_waiting": priority_waiting,
                    "priority_failed": priority_failed,
                    "priority_unaccounted": priority_unaccounted,
                    "priority_output_folders": priority_output_folders,
                },
            }
            if hypersafe_selected:
                activity.update({
                    "recovery.jobs_completed": str(priority_complete),
                    "recovery.files_incomplete": str(priority_waiting),
                    "recovery.files_failed": str(priority_failed),
                })
                recovered = max(
                    number(hypersafe, "recovered_total"),
                    priority_complete,
                )
                total_files = selected_files
            else:
                recovered = number(hypersafe, "recovered_total")
                total_files = 0
        elif (
            self._process is not None
            and self._process.poll() is None
            and not durable_state_is_current
        ):
            # No stable denominator exists yet.  A busy indicator is more
            # truthful than displaying a frozen 0% during backend preparation.
            phase = str(live.get("phase") or "Preparing filesystem metadata")
            recovered = 0
            total_files = 0
            operator_total = 0
            self.run_preview_progress.setRange(0, 0)
            self.run_percent_value.setText("STARTING")
            if hasattr(self, "run_post_scan_notice"):
                self.run_post_scan_notice.setVisible(False)
            self.run_cursor_value.setText("Preparing filesystem work plan")
            self.run_eta_value.setText("ESTIMATING")
            self.run_metric_values["PHASE"].setText(phase)
            self.run_metric_values["READ SPEED"].setText("measuring")
            self.run_metric_values["STALLED"].setText("active")
            activity = {
                "mode": (
                    self._current_mode_code()
                ),
                "scan.activity": phase,
            }
        ddrescue_supervisor_status = str(
            ddrescue_supervisor.get("status") or ""
        ).strip().lower()
        if (
            ddrescue_supervisor_current
            and ddrescue_supervisor_status in {
                "watching_kernel_io_stall",
                "kernel_io_hang",
            }
        ):
            ddrescue_phase = str(
                ddrescue_supervisor.get("phase") or "ddrescue image pass"
            ).strip()
            blocked_seconds = number(ddrescue_supervisor, "blocked_seconds")
            no_progress_seconds = number(
                ddrescue_supervisor,
                "no_progress_seconds",
            )
            activity = dict(activity)
            activity["activity.ddrescue"] = {
                "status": ddrescue_supervisor_status,
                "phase": ddrescue_phase,
                "blocked_seconds": blocked_seconds,
            }
            if ddrescue_supervisor_status == "kernel_io_hang":
                phase = f"Kernel I/O hang during {ddrescue_phase}"
                self.run_eta_value.setText("REBOOT REQUIRED")
                self.run_metric_values["STALLED"].setText(
                    f"D-state {blocked_seconds}s · no progress {no_progress_seconds}s"
                )
                self.run_state_value.setText("●  KERNEL I/O HANG")
                self.run_state_value.setStyleSheet(
                    f"color: #ff6975; font-family: '{mono_font_family()}'; font-size: 10px; "
                    "font-weight: 800; letter-spacing: 1px; border: none;"
                )
                self.stop_button.setText("REBOOT REQUIRED")
                self.stop_button.setEnabled(False)
                self._kernel_reboot_required = True
            else:
                phase = f"Watching slow kernel I/O during {ddrescue_phase}"
                self.run_eta_value.setText("WATCHING I/O")
                self.run_metric_values["STALLED"].setText(
                    f"D-state {blocked_seconds}s"
                )
            self.run_metric_values["PHASE"].setText(str(phase))
        self.run_metric_values["RECOVERED"].setText(f"{recovered:,}")
        self.run_metric_values["TOTAL FILES"].setText(f"{total_files:,}" if total_files > 0 else "—")
        self._sample_develop_run_time(
            phase=str(phase),
            stage=current_stage,
            activity=activity,
        )
        # Activity is the operator's heartbeat and must not wait behind disk-map
        # aggregation, which can parse large, growing evidence artifacts.
        self._update_operator_activity(
            state_dir,
            activity,
            phase=str(phase),
            offset=offset,
            total=operator_total,
            recovered=recovered,
        )
        evidence_mode = str(scan.get("scan_mode") or activity.get("mode") or "")
        hfs_evidence_ready = (
            hfs_active
            and hfs_phase not in {"planning", "preparing"}
        )
        if hfs_evidence_ready and not force_evidence:
            self._schedule_hfs_evidence_refresh(
                state_dir,
                evidence_total,
                scan_offset=evidence_offset,
                scan_mode=evidence_mode,
            )
        else:
            # Keep the established NTFS/raw evidence path synchronous and
            # unchanged; only live HFS+ yields before its larger map rebuild.
            self._update_cumulative_evidence(
                state_dir,
                evidence_total,
                scan_offset=evidence_offset,
                scan_mode=evidence_mode,
                force=force_evidence,
            )
        self._update_continue_image_button(
            state_dir,
            scan,
            hypersafe,
            ddrescue_supervisor,
            ddrescue_supervisor_current,
        )
        resource_now = time.monotonic()
        if resource_now - self._resource_sample_at < 2.0:
            return
        self._resource_sample_at = resource_now
        try:
            root_pid = self._process.pid if self._process else 0
            resource_lines = subprocess.run(
                ["ps", "-axo", "pid=,ppid=,%cpu=,rss="],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            ).stdout.splitlines()
            rows = []
            children = {}
            for line in resource_lines:
                parts = line.split()
                if len(parts) != 4:
                    continue
                pid, ppid = int(parts[0]), int(parts[1])
                rows.append((pid, float(parts[2]), int(parts[3])))
                children.setdefault(ppid, []).append(pid)
            family = {root_pid}
            pending = [root_pid]
            while pending:
                child_ids = children.get(pending.pop(), [])
                for child_pid in child_ids:
                    if child_pid not in family:
                        family.add(child_pid)
                        pending.append(child_pid)
            family_rows = [row for row in rows if row[0] in family]
            if family_rows:
                cpu = sum(row[1] for row in family_rows)
                total_cpu = max(100, int(os.cpu_count() or 1) * 100)
                ram_kib = sum(row[2] for row in family_rows)
                self.run_cpu_value.setText(
                    f"{cpu:.0f}% "
                    f"<sub><span style=\"color:{MUTED}; font-size:10px;\">"
                    f"/ {total_cpu}%</span></sub>"
                )
                self.run_ram_value.setText(f"{ram_kib / 1024:.0f} MiB")
        except (OSError, ValueError, subprocess.SubprocessError):
            pass

    def _update_continue_image_button(
        self,
        state_dir: Path,
        scan_state: dict,
        hypersafe_state: dict,
        ddrescue_supervisor_state: dict,
        ddrescue_supervisor_current: bool,
    ) -> None:
        if not hasattr(self, "continue_image_button"):
            return
        process_live = self._process is not None and self._process.poll() is None
        hypersafe_run = any(
            option in self._run_command_parts
            for option in ("--hypersafe", "--hypersafe-recover")
        )
        hypersafe_selected = "--hypersafe-recover" in self._run_command_parts
        hypersafe_stage = str(
            hypersafe_state.get("stage") or ""
        ).strip().lower()
        ddrescue_status = str(
            ddrescue_supervisor_state.get("status") or ""
        ).strip().lower()
        ddrescue_continue_available = str(
            ddrescue_supervisor_state.get("continue_available") or ""
        ).strip().lower() in {"1", "true", "yes"}
        ddrescue_active = bool(
            ddrescue_supervisor_current
            and ddrescue_status in {"active", "watching_kernel_io_stall"}
        )
        hypersafe_imaging = (
            hypersafe_selected
            and (
                ddrescue_active
                or hypersafe_stage in {
                    "full_image_quick",
                    "remaining_image_retries",
                }
            )
        )
        status = self._read_state_file(state_dir / "source_image_status.txt")
        finished = str(status.get("status") or "").strip().lower() in {
            "ok", "partial_continue", "failed", "done", "completed",
        }
        scan_started = bool(scan_state.get("scan_mode"))
        legacy_image_active = bool(
            self._run_requested_make_image_first
            and not hypersafe_run
            and not finished
            and not scan_started
        )
        fallback_hypersafe_continue = bool(
            hypersafe_imaging and not ddrescue_active
        )
        active = (
            process_live
            and (
                ddrescue_active
                or hypersafe_imaging
                or legacy_image_active
            )
        )
        hypersafe_immediate = any(
            self._run_command_parts[index:index + 2] == ["--hypersafe", "immediate"]
            for index in range(max(0, len(self._run_command_parts) - 1))
        )
        self._ddrescue_continue_available = bool(
            (ddrescue_active and ddrescue_continue_available)
            or fallback_hypersafe_continue
            or legacy_image_active
        )
        self._ddrescue_image_only_run = bool(
            "--image-only" in self._run_command_parts or hypersafe_immediate
        )
        request_path = state_dir / "source_image_continue_requested"
        stop_pending = bool(getattr(self, "_stop_requested", False))
        requested = (
            self._continue_image_requested
            or stop_pending
            or self._path_exists(request_path)
        )
        self.continue_image_button.setVisible(active)
        self.continue_image_button.setEnabled(active and not requested)
        if stop_pending:
            button_text = "STOP REQUESTED…"
        elif requested:
            button_text = (
                "KEEPING PARTIAL IMAGE…"
                if self._ddrescue_image_only_run
                else "CONTINUING FROM IMAGE…"
            )
        elif self._ddrescue_continue_available:
            button_text = (
                "STOP IMAGING · KEEP PARTIAL IMAGE"
                if self._ddrescue_image_only_run
                else "STOP IMAGING · RECOVER FROM IMAGE"
            )
        else:
            button_text = "STOP DDRESCUE · SAVE MAP"
        self.continue_image_button.setText(button_text)
        if not self._ddrescue_continue_available:
            tooltip = (
                "Stop ddrescue cleanly and keep the partial image and map for Resume."
            )
        elif self._ddrescue_image_only_run:
            tooltip = "Stop ddrescue cleanly and keep the partial image and map."
        else:
            tooltip = (
                "Stop ddrescue cleanly, skip remaining source retries in this run, "
                "and recover files from the partial image."
            )
        self.continue_image_button.setToolTip(tooltip)

    def _request_continue_from_source_image(self) -> None:
        if self._process is None or self._process.poll() is not None or self._current_run_dir is None:
            return
        if not self._ddrescue_continue_available:
            self._request_stop_ddrescue_with_saved_map()
            return
        image_only = self._ddrescue_image_only_run
        if image_only:
            title = "Stop imaging and keep partial image"
            prompt = (
                "Stop ddrescue cleanly, keep the partial image, and finish this "
                "image-only run now?\n\n"
            )
        else:
            title = "Stop imaging and recover from image"
            prompt = (
                "Stop ddrescue cleanly, skip the remaining source retries in this run, "
                "and continue file recovery from the partial image?\n\n"
            )
        prompt += (
            "Unread source regions remain recorded in the ddrescue map and can be "
            "revisited with Resume later."
        )
        answer = QMessageBox.warning(
            self,
            title,
            prompt,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        request_path = self._current_run_dir / "state" / "source_image_continue_requested"
        try:
            if not request_path.parent.is_dir():
                raise OSError(f"State directory is unavailable: {request_path.parent}")
            request_path.write_text(
                f"requested_unix={time.time():.3f}\nreason=operator_continue_from_partial_image\n",
                encoding="utf-8",
            )
        except OSError as exc:
            QMessageBox.warning(self, "Stop and use image now", f"Could not write the request:\n\n{exc}")
            return
        self._continue_image_requested = True
        self.continue_image_button.setText(
            "KEEPING PARTIAL IMAGE…" if image_only else "CONTINUING FROM IMAGE…"
        )
        self.continue_image_button.setEnabled(False)
        self._append_gui_event(
            "imaging_stop_requested",
            image_only=image_only,
        )

    def _request_stop_ddrescue_with_saved_map(self) -> None:
        answer = QMessageBox.warning(
            self,
            "Stop ddrescue and save map",
            "This ddrescue pass is preparing source identity or filesystem metadata, "
            "so Carv cannot safely jump to file recovery yet.\n\n"
            "Stop the current recovery cleanly and keep its partial image and map "
            "for Resume?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        sent, survivors = self._signal_recovery_process_tree(
            signal.SIGINT,
            title="Stop ddrescue and save map",
            prompt="Authenticate to stop ddrescue and preserve its image/map.",
            button_text="Stop ddrescue",
        )
        if sent:
            self._set_clean_stop_pending(
                survivors,
                kind="ddrescue",
            )

    @staticmethod
    def _system_process_table() -> dict[int, tuple[int, int, str]]:
        try:
            lines = subprocess.run(
                ["ps", "-axo", "pid=,ppid=,pgid=,state="],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            ).stdout.splitlines()
        except (OSError, subprocess.SubprocessError):
            return {}
        table = {}
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                pid, ppid, pgid = (int(parts[0]), int(parts[1]), int(parts[2]))
            except ValueError:
                continue
            table[pid] = (ppid, pgid, parts[3][:1].upper())
        return table

    def _refresh_recovery_process_family(
        self,
        *,
        force: bool = False,
    ) -> tuple[set[int], set[int]]:
        now = time.monotonic()
        if not force and now - self._process_family_cache_at < 2.0:
            cached_pids = set(self._process_family_cache[1])
            cached_pgids = set(self._process_family_cache[2])
            return cached_pids, cached_pgids
        table = self._system_process_table()
        if not table:
            return set(self._recovery_known_pids), set(self._recovery_known_pgids)
        roots = set(self._recovery_known_pids)
        if self._process is not None:
            roots.add(self._process.pid)
        family = {
            pid for pid in roots
            if pid in table and table[pid][2] != "Z"
        }
        changed = True
        while changed:
            changed = False
            for pid, (ppid, _pgid, state) in table.items():
                if state != "Z" and ppid in family and pid not in family:
                    family.add(pid)
                    changed = True
        own_pgid = os.getpgrp()
        pgids = {
            table[pid][1] for pid in family
            if table[pid][1] > 0 and table[pid][1] != own_pgid
        }
        self._recovery_known_pids = family
        self._recovery_known_pgids = pgids
        self._process_family_cache_at = now
        self._process_family_cache = (table, set(family), set(pgids))
        return set(family), set(pgids)

    def _signal_recovery_process_tree(
        self,
        sig: signal.Signals,
        *,
        title: str,
        prompt: str,
        button_text: str,
    ) -> tuple[bool, set[int]]:
        pids, pgids = self._refresh_recovery_process_family(force=True)
        process = self._process
        if process is not None and process.poll() is None:
            pids.add(process.pid)
            try:
                pgid = os.getpgid(process.pid)
                if pgid > 0 and pgid != os.getpgrp():
                    pgids.add(pgid)
            except OSError:
                pass
        if not pids and not pgids:
            return True, set()

        signal_name = "-KILL" if int(sig) == int(signal.SIGKILL) else "-INT"
        table = self._system_process_table()
        clean_stop_pids = set()
        if int(sig) == int(signal.SIGINT) and process is not None:
            if self._process_started_with_sudo:
                clean_stop_pids = {
                    pid for pid, (ppid, _pgid, state) in table.items()
                    if ppid == process.pid and state != "Z"
                }
            if not clean_stop_pids and process.poll() is None:
                clean_stop_pids = {process.pid}
        try:
            if self._process_started_with_sudo:
                helper = app_runtime_root() / "scripts" / "carv_gui_askpass.py"
                env = os.environ.copy()
                env.update({
                    "SUDO_ASKPASS": str(helper),
                    "CARV_ASKPASS_TITLE": title,
                    "CARV_ASKPASS_PROMPT": prompt,
                    "CARV_ASKPASS_OK": button_text,
                    "CARV_ASKPASS_CANCEL": "Cancel",
                })
                if int(sig) == int(signal.SIGINT):
                    # Signal the outer Carv supervisor once. It owns graceful
                    # propagation to its worker/ddrescue group; broadcasting
                    # SIGINT to every group would make a child see two stops.
                    targets = [str(pid) for pid in sorted(clean_stop_pids)]
                else:
                    targets = [f"-{pgid}" for pgid in sorted(pgids)]
                    covered = {
                        pid for pid in pids
                        if pid in table and table[pid][1] in pgids
                    }
                    targets.extend(str(pid) for pid in sorted(pids - covered))
                if targets:
                    result = subprocess.run(
                        ["sudo", "-A", "kill", signal_name, "--", *targets],
                        cwd=str(app_runtime_root()),
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=20,
                        check=False,
                    )
                    if result.returncode != 0:
                        time.sleep(0.15)
                        survivors, _ = self._refresh_recovery_process_family(force=True)
                        if survivors:
                            raise OSError(
                                (result.stderr or result.stdout or "sudo kill failed").strip()
                            )
            else:
                if int(sig) == int(signal.SIGINT):
                    direct_targets = clean_stop_pids
                    signal_pgids = set()
                else:
                    direct_targets = pids
                    signal_pgids = pgids
                for pgid in sorted(signal_pgids):
                    try:
                        os.killpg(pgid, int(sig))
                    except ProcessLookupError:
                        pass
                covered = {
                    pid for pid in direct_targets
                    if pid in table and table[pid][1] in signal_pgids
                }
                for pid in sorted(direct_targets - covered):
                    try:
                        os.kill(pid, int(sig))
                    except ProcessLookupError:
                        pass
            time.sleep(0.15)
            survivors, _ = self._refresh_recovery_process_family(force=True)
            return True, survivors
        except (OSError, subprocess.TimeoutExpired) as exc:
            QMessageBox.warning(self, title, f"Could not signal the complete recovery tree:\n\n{exc}")
            survivors, _ = self._refresh_recovery_process_family(force=True)
            return False, survivors

    def _set_clean_stop_pending(
        self,
        survivors: set[int],
        *,
        kind: str,
    ) -> None:
        self._stop_requested = True
        self.continue_image_button.setText("STOP REQUESTED…")
        self.continue_image_button.setEnabled(False)
        self.stop_button.setText("KILL RECOVERY")
        self.stop_button.setToolTip(
            "The clean stop is pending. Click to force-kill the complete process group."
        )
        self.stop_button.setStyleSheet(
            "QPushButton { color: #fff0f0; border-color: #c84f59; background: #511d24; "
            "font-weight: 800; letter-spacing: 0.8px; padding: 8px 16px; }"
            "QPushButton:hover { border-color: #ff6975; background: #70252e; }"
        )
        self._append_gui_event(
            "clean_stop_requested",
            kind=kind,
            survivors=sorted(survivors),
        )

    def _stop_recovery(self) -> None:
        process = self._process
        live_family, _ = self._refresh_recovery_process_family(force=True)
        if (process is None or process.poll() is not None) and not live_family:
            return
        if self._stop_requested:
            answer = QMessageBox.warning(
                self,
                "Kill recovery",
                "Force-kill the complete carv process group now?\n\n"
                "Open output files may be incomplete. A process blocked in kernel disk I/O "
                "can remain visible until the operating system releases that I/O.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            sent, survivors = self._signal_recovery_process_tree(
                signal.SIGKILL,
                title="Kill recovery",
                prompt="Authenticate to force-kill the complete recovery process tree.",
                button_text="Kill recovery",
            )
            if sent:
                self.stop_button.setText("KILL SENT · VERIFYING" if survivors else "KILL SENT")
                self.stop_button.setEnabled(bool(survivors))
                self._append_gui_event(
                    "forced_kill",
                    survivors=sorted(survivors),
                )
            return
        answer = QMessageBox.question(
            self,
            "Stop recovery",
            "Send an interrupt to carv so it can stop cleanly?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        sent, survivors = self._signal_recovery_process_tree(
            signal.SIGINT,
            title="Stop recovery",
            prompt="Authenticate to stop the complete recovery process tree cleanly.",
            button_text="Stop recovery",
        )
        if sent:
            self._set_clean_stop_pending(
                survivors,
                kind="recovery",
            )

    def _update_plan_mode_ui(self, mode_text: str) -> None:
        image_only_mode = self._mode_text_is_image_only(mode_text)
        if not self._syncing_image_only_mode:
            if image_only_mode:
                if (
                    hasattr(self, "image_only_check")
                    and not self.image_only_check.isChecked()
                ):
                    self._syncing_image_only_mode = True
                    try:
                        self.image_only_check.setChecked(True)
                    finally:
                        self._syncing_image_only_mode = False
            else:
                self._mode_before_image_only = str(mode_text or "Raw File Hunt")
                if (
                    hasattr(self, "image_only_check")
                    and self.image_only_check.isChecked()
                ):
                    self._syncing_image_only_mode = True
                    try:
                        self.image_only_check.setChecked(False)
                    finally:
                        self._syncing_image_only_mode = False
        if not hasattr(self, "plan_tabs") or self.plan_tabs.count() < 2:
            return
        signature_mode = self._mode_text_is_raw_hunt(mode_text)
        filesystem_mode = self._mode_text_is_tree_recovery(mode_text)
        self.plan_tabs.setTabText(1, "FILTERS")
        self.plan_tab_bar.set_highlighted_index(-1)
        self.plan_tabs.setTabToolTip(
            1,
            "Choose the file types to recover in the active mode."
            if (signature_mode or filesystem_mode)
            else "Optional recovery filters.",
        )
        self._set_all_types_visibility(False)
        self._refresh_setup_eta()
        self._refresh_plan_status()

    def _build_plan_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(9)

        self.service_id_combo = TechnicalComboBox(editable=True)
        self.service_id_combo.addItems(self._recent_service_ids)
        self.service_id_combo.setCurrentIndex(-1)
        self.service_id_combo.lineEdit().setPlaceholderText("Enter or choose a recent Service ID")
        self.service_id_combo.currentTextChanged.connect(self._refresh_plan_status)
        layout.addWidget(labeled_field("SERVICE ID", self.service_id_combo))

        self.mode_combo = TechnicalComboBox()
        self.mode_combo.addItems(
            [
                "Tree Recovery",
                "Raw File Hunt",
                "Image only",
                "Name existing carved files",
            ]
        )
        self.mode_combo.setCurrentIndex(1)
        self.mode_combo.currentTextChanged.connect(self._update_plan_mode_ui)
        layout.addWidget(labeled_field("MODE", self.mode_combo))

        strategy_label = QLabel("IMAGE STRATEGY")
        strategy_label.setStyleSheet(
            f"color: {MUTED}; font-family: '{mono_font_family()}'; font-size: 10px; "
            "font-weight: 700; letter-spacing: 0.8px;"
        )
        layout.addWidget(strategy_label)
        self.image_first_check = QCheckBox("Create image first")
        self.image_first_check.setChecked(True)
        self.image_first_check.setToolTip(
            "Create a ddrescue image of the full source before recovery. "
            "Selected folders limit recovery from the image, never the imaging scope."
        )
        self.deep_image_check = QCheckBox("Deep ddrescue pass")
        self.image_only_check = QCheckBox("Image only")
        self.image_only_check.setToolTip(
            "Run ddrescue image creation/update and exit before any carving or metadata recovery."
        )
        self.hypersafe_folder_fetch_button = QPushButton("Fetch MFT and show folder tree")
        self.hypersafe_folder_fetch_button.setEnabled(False)
        self.hypersafe_folder_fetch_button.setToolTip(
            "Create a sparse ddrescue image containing disk headers and NTFS $MFT, then show its folder tree."
        )
        self.hypersafe_folder_fetch_button.setFixedHeight(28)
        self.hypersafe_folder_fetch_button.setStyleSheet(
            f"QPushButton {{ background: #14191e; color: {MUTED}; border: 1px solid {BORDER}; "
            "border-radius: 4px; padding: 4px 10px; font-family: '"
            f"{mono_font_family()}'; font-size: 10px; font-weight: 800; letter-spacing: 0.7px; }}"
        )
        self.hypersafe_folder_fetch_button.clicked.connect(
            self._run_hypersafe_folder_fetch
        )
        self.hypersafe_folder_fetch_button.setVisible(False)
        self.hypersafe_enabled_check = QCheckBox("Hypersafe recovery")
        self.hypersafe_enabled_check.setToolTip(
            "Use the Hypersafe imaging workflow. Its detailed strategy appears "
            "below Source and Output."
        )
        self.hypersafe_enabled_check.toggled.connect(
            self._toggle_hypersafe_layout_panel
        )
        self.hypersafe_enabled_check.setVisible(
            HYPERSAFE_UI_VISIBLE
        )
        self.image_first_check.toggled.connect(self.deep_image_check.setEnabled)
        self.image_first_check.toggled.connect(self._refresh_command_preview)
        self.deep_image_check.toggled.connect(self._refresh_command_preview)
        self.image_only_check.toggled.connect(self._on_image_only_changed)
        layout.addWidget(self.image_first_check)
        layout.addWidget(self.deep_image_check)
        layout.addWidget(self.hypersafe_enabled_check)
        layout.addWidget(self.image_only_check)

        layout.addStretch(1)
        return tab

    def _build_filter_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(9)

        self.type_filter_tabs = QTabWidget()
        self.type_filter_tabs.setDocumentMode(False)
        self.type_filter_tabs.tabBar().setExpanding(False)
        self.type_filter_tabs.setStyleSheet(
            "QTabBar::tab { min-width: 92px; padding-left: 14px; padding-right: 14px; }"
        )
        self.type_filter_tabs.addTab(self._build_categories_tab(), "CATEGORIES")
        self.type_filter_tabs.addTab(self._build_formats_tab(), "FORMATS")
        self.type_filter_tabs.setMaximumHeight(155)
        self.type_filter_tabs.currentChanged.connect(self._refresh_command_preview)
        self.type_filter_tabs.currentChanged.connect(lambda *_: self._refresh_plan_status())
        layout.addWidget(self.type_filter_tabs)

        self.date_filter_label = QLabel("DATE RANGE")
        self.date_filter_label.setStyleSheet(
            f"QLabel {{ color: {MUTED}; font-family: '{mono_font_family()}'; font-size: 10px; "
            "font-weight: 700; letter-spacing: 0.8px; } "
            "QLabel:disabled { color: #747d85; }"
        )
        layout.addWidget(self.date_filter_label)
        date_row = QHBoxLayout()
        self.date_from_edit = QLineEdit()
        self.date_from_edit.setPlaceholderText("YYYY-MM-DD")
        self.date_to_edit = QLineEdit()
        self.date_to_edit.setPlaceholderText("YYYY-MM-DD")
        self._date_to_is_auto = False
        self._copying_date_to = False
        self.date_from_edit.textChanged.connect(self._mirror_date_from_to)
        self.date_to_edit.textChanged.connect(self._note_manual_date_to_change)
        self.date_from_edit.textChanged.connect(self._refresh_command_preview)
        self.date_to_edit.textChanged.connect(self._refresh_command_preview)
        self.date_from_edit.textChanged.connect(lambda *_: self._refresh_plan_status())
        self.date_to_edit.textChanged.connect(lambda *_: self._refresh_plan_status())
        self.date_filter_separator = QLabel("TO")
        self.date_filter_separator.setStyleSheet(
            f"QLabel {{ color: {MUTED}; font-family: '{mono_font_family()}'; font-size: 9px; }} "
            "QLabel:disabled { color: #747d85; }"
        )
        date_row.addWidget(self.date_from_edit)
        date_row.addWidget(self.date_filter_separator)
        date_row.addWidget(self.date_to_edit)
        layout.addLayout(date_row)

        self.file_state_label = QLabel("FILE STATE")
        self.file_state_label.setStyleSheet(
            f"QLabel {{ color: {MUTED}; font-family: '{mono_font_family()}'; font-size: 10px; "
            "font-weight: 700; letter-spacing: 0.8px; } "
            "QLabel:disabled { color: #747d85; }"
        )
        layout.addWidget(self.file_state_label)
        state_row = QHBoxLayout()
        self.file_state_radios = {}
        for text, checked in (("All states", True), ("Live", False), ("Deleted", False)):
            option = QRadioButton(text)
            option.setChecked(checked)
            option.toggled.connect(self._refresh_command_preview)
            self.file_state_radios[text] = option
            state_row.addWidget(option)
        state_row.addStretch(1)
        layout.addLayout(state_row)

        layout.addStretch(1)
        return tab

    def _note_manual_date_to_change(self, _value: str) -> None:
        if not self._copying_date_to:
            self._date_to_is_auto = False

    def _mirror_date_from_to(self, value: str) -> None:
        """Seed the end date from the start date until the operator edits it."""
        if not hasattr(self, "date_to_edit"):
            return
        if not value and not self._date_to_is_auto:
            return
        if self.date_to_edit.text() and not self._date_to_is_auto:
            return
        self._copying_date_to = True
        try:
            self.date_to_edit.setText(value)
            self._date_to_is_auto = bool(value)
        finally:
            self._copying_date_to = False

    def _build_advanced_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(12)

        self.filesystem_combo = TechnicalComboBox()
        self.filesystem_combo.addItems(["Auto detect", "NTFS", "HFS+"])
        self.filesystem_combo.currentTextChanged.connect(self._refresh_command_preview)
        self.filesystem_combo.currentTextChanged.connect(self._update_hfs_filter_availability)
        layout.addWidget(labeled_field("FILESYSTEM", self.filesystem_combo))
        self._update_hfs_filter_availability(self.filesystem_combo.currentText())

        self.start_position_slider = QSlider(Qt.Orientation.Horizontal)
        self.start_position_slider.setRange(0, 100)
        self.start_position_slider.setValue(0)
        self.start_position_control = labeled_slider(
            "START POSITION", "Start of source", self.start_position_slider
        )
        self.start_position_control.value_label.setToolTip("Click to type an exact byte offset for --start")
        self.start_position_control.value_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.start_position_control.value_label.setStyleSheet(
            f"color: {ACCENT}; font-family: '{mono_font_family()}'; font-size: 11px; text-decoration: underline;"
        )
        self.start_position_control.value_label.mousePressEvent = (
            lambda event: self._edit_advanced_byte_value("start")
        )
        self.start_position_slider.valueChanged.connect(self._on_start_position_slider_changed)
        self.start_position_slider.valueChanged.connect(self._refresh_command_preview)
        self.start_position_slider.sliderMoved.connect(self._refresh_command_preview)
        self.start_position_slider.actionTriggered.connect(self._refresh_command_preview)
        layout.addWidget(self.start_position_control)

        self.limit_bytes_slider = QSlider(Qt.Orientation.Horizontal)
        self.limit_bytes_slider.setRange(1, 100)
        self.limit_bytes_slider.setValue(100)
        self.limit_bytes_control = labeled_slider("LIMIT BYTES", "Unlimited", self.limit_bytes_slider)
        self.limit_bytes_control.value_label.setToolTip("Click to type an exact byte count for --limit")
        self.limit_bytes_control.value_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.limit_bytes_control.value_label.setStyleSheet(
            f"color: {ACCENT}; font-family: '{mono_font_family()}'; font-size: 11px; text-decoration: underline;"
        )
        self.limit_bytes_control.value_label.mousePressEvent = (
            lambda event: self._edit_advanced_byte_value("limit")
        )
        self.limit_bytes_slider.valueChanged.connect(self._on_limit_bytes_slider_changed)
        self.limit_bytes_slider.valueChanged.connect(self._refresh_command_preview)
        self.limit_bytes_slider.sliderMoved.connect(self._refresh_command_preview)
        self.limit_bytes_slider.actionTriggered.connect(self._refresh_command_preview)
        layout.addWidget(self.limit_bytes_control)

        caution = QLabel("Advanced limits affect the physical read plan. Verify them before source activation.")
        caution.setWordWrap(True)
        caution.setStyleSheet(f"color: {MUTED}; font-size: 11px;")
        layout.addWidget(caution)
        layout.addStretch(1)
        return tab

    def _on_start_position_slider_changed(self, *_args) -> None:
        self._manual_start_bytes = None
        self._update_advanced_preview()

    def _on_limit_bytes_slider_changed(self, *_args) -> None:
        self._manual_limit_bytes = None
        self._update_advanced_preview()

    def _edit_advanced_byte_value(self, which: str) -> None:
        is_start = which == "start"
        title = "Set start byte" if is_start else "Set limit bytes"
        label = (
            "Exact byte offset for --start. Empty or 0 clears it."
            if is_start
            else "Exact byte count for --limit. Empty or 0 clears it."
        )
        current = self._manual_start_bytes if is_start else self._manual_limit_bytes
        if current is None:
            current_text = ""
        else:
            current_text = str(max(0, int(current)))
        text, ok = QInputDialog.getText(
            self,
            title,
            label,
            QLineEdit.EchoMode.Normal,
            current_text,
        )
        if not ok:
            return
        parsed = self._parse_byte_text(text)
        if parsed is None:
            QMessageBox.warning(
                self,
                "Invalid byte value",
                "Write bytes as a plain number, hex like 0x100000, or a size like 512MiB."
            )
            return
        if is_start:
            self._manual_start_bytes = parsed if parsed > 0 else None
            if parsed > 0 and hasattr(self, "start_position_slider"):
                self.start_position_slider.blockSignals(True)
                self.start_position_slider.setValue(0)
                self.start_position_slider.blockSignals(False)
        else:
            self._manual_limit_bytes = parsed if parsed > 0 else None
            if hasattr(self, "limit_bytes_slider"):
                self.limit_bytes_slider.blockSignals(True)
                self.limit_bytes_slider.setValue(self._slider_percent_for_manual_limit(parsed))
                self.limit_bytes_slider.blockSignals(False)
        self._update_advanced_preview()

    def _current_advanced_start_bytes(self) -> int:
        if self._manual_start_bytes is not None:
            return max(0, int(self._manual_start_bytes))
        if not self._selected_source or not hasattr(self, "start_position_slider"):
            return 0
        source_size = max(0, int(self._selected_source.get("size_bytes") or 0))
        if source_size <= 0:
            return 0
        start_ratio = self.start_position_slider.value() / max(1, self.start_position_slider.maximum())
        return max(0, round(source_size * start_ratio))

    def _active_run_scope_from_command(self, source_size: int = 0) -> tuple[int, int, int] | None:
        parts = list(getattr(self, "_run_command_parts", []) or [])
        if not parts:
            return None

        def option_value(name: str) -> str | None:
            try:
                index = parts.index(name)
            except ValueError:
                return None
            if index + 1 >= len(parts):
                return None
            return parts[index + 1]

        mode = (option_value("--mode") or "").strip().lower()
        if mode and mode not in {"all", "raw", "signature", "signatures"}:
            return None

        full_size = max(
            0,
            int(source_size or 0),
            int((self._selected_source or {}).get("size_bytes") or 0),
        )
        if full_size <= 0:
            return None

        def parse_u64(text: str | None) -> int:
            try:
                return max(0, int(str(text or "").strip()))
            except (TypeError, ValueError):
                return 0

        start = min(parse_u64(option_value("--start")), full_size)
        limit = parse_u64(option_value("--limit"))
        end = min(full_size, start + limit) if limit > 0 else full_size
        if end <= start:
            return None
        return start, end, full_size

    def _slider_percent_for_manual_limit(self, limit_bytes: int) -> int:
        limit_bytes = max(0, int(limit_bytes or 0))
        if limit_bytes <= 0:
            return 100
        if not self._selected_source:
            return 100
        source_size = max(0, int(self._selected_source.get("size_bytes") or 0))
        remaining = max(0, source_size - self._current_advanced_start_bytes())
        if remaining <= 0:
            return 100
        percent = round((limit_bytes / remaining) * 100.0)
        return max(1, min(100, int(percent)))

    def _update_advanced_preview(self, *_args) -> None:
        if hasattr(self, "start_position_control"):
            if self._manual_start_bytes is not None:
                self.start_position_control.value_label.setText(
                    self._format_advanced_byte_value(
                        self._manual_start_bytes,
                        zero_text="Start of source",
                    )
                )
            else:
                start = self.start_position_slider.value()
                self.start_position_control.value_label.setText(
                    "Start of source" if start == 0 else f"{start}% of source"
                )
        if hasattr(self, "limit_bytes_control"):
            if self._manual_limit_bytes is not None:
                self.limit_bytes_control.value_label.setText(
                    self._format_advanced_byte_value(
                        self._manual_limit_bytes,
                        zero_text="Unlimited",
                    )
                )
            else:
                limit = self.limit_bytes_slider.value()
                self.limit_bytes_control.value_label.setText(
                    "Unlimited" if limit == 100 else (
                        f"{limit}% of remaining source"
                    )
                )
        self._refresh_command_preview()

    def _build_categories_tab(self) -> QWidget:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(10, 8, 10, 8)
        outer.setSpacing(4)
        outer.addLayout(self._filter_bulk_action_row("category"))

        grid_host = QWidget()
        layout = QGridLayout(grid_host)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setHorizontalSpacing(26)
        layout.setVerticalSpacing(9)
        self.category_layout = layout

        self.category_all_types_box = QCheckBox("All types")
        self.category_all_types_box.setVisible(False)
        self.category_all_types_box.toggled.connect(
            lambda checked: self._handle_all_types_toggled("category", checked)
        )

        items = (
            ("Pictures", False),
            ("Documents", False),
            ("Video", False),
            ("Audio", False),
            ("Archives", False),
            ("All", True),
        )
        self.category_boxes = {}
        for index, (label, checked) in enumerate(items):
            box = QCheckBox(label)
            box.setChecked(checked)
            self._remember_filter_selection("category", label, checked)
            box.toggled.connect(self._refresh_command_preview)
            box.toggled.connect(lambda *_: self._refresh_plan_status())
            box.toggled.connect(lambda *_: self._sync_all_types_from_children("category"))
            box.toggled.connect(
                lambda checked, label=label: self._on_category_filter_toggled(label, checked)
            )
            self.category_boxes[label] = box

        self._relayout_filter_grid("category")
        outer.addWidget(grid_host, 1)
        return tab

    def _build_formats_tab(self) -> QWidget:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(10, 8, 10, 8)
        outer.setSpacing(4)
        outer.addLayout(self._filter_bulk_action_row("format"))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        content.setStyleSheet(f"background: {TAB_ACTIVE};")
        layout = QGridLayout(content)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setHorizontalSpacing(26)
        layout.setVerticalSpacing(9)
        self.format_layout = layout

        self.format_all_types_box = QCheckBox("All types")
        self.format_all_types_box.setVisible(False)
        self.format_all_types_box.toggled.connect(
            lambda checked: self._handle_all_types_toggled("format", checked)
        )

        available_formats = self._available_carv_formats()
        default_formats = self._default_format_selection()
        items = tuple((fmt, fmt in default_formats) for fmt in available_formats)
        self.format_boxes = {}
        for index, (label, checked) in enumerate(items):
            box = QCheckBox(label)
            box.setChecked(checked)
            self._remember_filter_selection("format", label, checked)
            box.toggled.connect(self._refresh_command_preview)
            box.toggled.connect(lambda *_: self._refresh_plan_status())
            box.toggled.connect(lambda *_: self._sync_all_types_from_children("format"))
            box.toggled.connect(
                lambda checked, label=label: self._remember_filter_selection(
                    "format", label, checked
                )
            )
            self.format_boxes[label] = box

        self._relayout_filter_grid("format")
        self._sync_formats_from_categories()

        scroll.setWidget(content)
        outer.addWidget(scroll)
        return tab

    def _filter_bulk_action_row(self, group: str) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(5)
        label = QLabel("SELECT")
        label.setStyleSheet(
            f"color: {MUTED}; font-family: '{mono_font_family()}'; font-size: 9px; "
            "font-weight: 700; letter-spacing: 0.7px;"
        )
        all_button = QPushButton("ALL")
        none_button = QPushButton("NONE")
        for button, tooltip, color in (
            (all_button, "Select every item in this list.", ACCENT),
            (none_button, "Clear every item in this list.", MUTED),
        ):
            button.setToolTip(tooltip)
            button.setFixedHeight(22)
            button.setStyleSheet(
                f"QPushButton {{ background: #14191e; color: {color}; border: 1px solid {BORDER}; "
                "border-radius: 3px; padding: 2px 8px; font-family: '"
                f"{mono_font_family()}'; font-size: 9px; font-weight: 700; letter-spacing: 0.6px; }} "
                f"QPushButton:hover {{ background: #1b2b23; border-color: {ACCENT}; color: {ACCENT}; }}"
            )
        all_button.clicked.connect(lambda: self._set_filter_group_checked(group, True))
        none_button.clicked.connect(lambda: self._set_filter_group_checked(group, False))
        row.addWidget(label)
        row.addWidget(all_button)
        row.addWidget(none_button)
        row.addStretch(1)
        return row

    def _set_filter_group_checked(self, group: str, checked: bool) -> None:
        boxes, master = self._boxes_for_all_types_group(group)
        for label, box in boxes.items():
            blocked = box.blockSignals(True)
            box.setChecked(checked)
            box.blockSignals(blocked)
            self._remember_filter_selection(group, label, checked)
        if master is not None and master.isVisible():
            blocked = master.blockSignals(True)
            master.setChecked(checked)
            master.blockSignals(blocked)
        if group == "category":
            self._sync_formats_from_categories()
        self._refresh_command_preview()
        self._refresh_plan_status()

    def _boxes_for_all_types_group(self, group: str):
        if group == "category":
            return getattr(self, "category_boxes", {}), getattr(self, "category_all_types_box", None)
        return getattr(self, "format_boxes", {}), getattr(self, "format_all_types_box", None)

    def _remember_filter_selection(self, group: str, label: str, checked: bool) -> None:
        cache = getattr(self, "_filter_selection_cache", None)
        if not isinstance(cache, dict):
            return
        cache.setdefault(group, {})[str(label)] = bool(checked)

    def _on_category_filter_toggled(self, label: str, checked: bool) -> None:
        self._remember_filter_selection("category", label, checked)
        self._sync_formats_from_categories()
        self._refresh_command_preview()
        self._refresh_plan_status()

    @staticmethod
    def _category_format_presets() -> dict[str, set[str]]:
        image = {
            "jpg", "jpeg", "jp2", "webp", "png", "gif", "bmp", "dib",
            "tif", "tiff", "psd", "heic", "heif", "avif",
        }
        raw = {
            "dng", "cr2", "cr3", "crw", "nef", "nrw", "arw", "sr2",
            "srf", "arq", "orf", "ori", "rw2", "rwl", "raw", "pef",
            "ptx", "srw", "raf", "x3f", "3fr", "fff", "iiq", "mos",
        }
        video = {
            "mov", "mp4", "m4v", "mkv", "avi", "wmv", "asf", "mpg",
            "vob", "3gp", "3g2", "rm", "rmvb", "ivr",
        }
        audio = {
            "mp3", "m4a", "m4b", "wav", "flac", "ra", "mid", "midi",
            "rmi", "wma", "aac", "ast",
        }
        documents = {
            "pdf", "fdf", "doc", "dot", "docx", "xls", "xla", "xlsx",
            "ppt", "pps", "wiz", "pptx", "odt", "ods", "odp", "epub",
            "xps", "msg", "mdb", "vsd", "pub", "ole", "sqlite", "db",
            "lrcat",
        }
        archives = {"zip", "apk", "jar", "rar", "7z", "gz", "lha", "lzh", "iso"}
        return {
            "Pictures": image,
            "Documents": documents,
            "Video": video,
            "Audio": audio,
            "Archives": archives,
            "All": image | raw | video | audio | documents | archives,
        }

    def _formats_for_selected_categories(self) -> set[str]:
        selected_categories = {
            label
            for label, checked in getattr(self, "_filter_selection_cache", {})
            .get("category", {})
            .items()
            if checked
        }
        if not selected_categories:
            return set()
        available = set(getattr(self, "format_boxes", {}).keys())
        if not available:
            available = set(self._available_carv_formats())
        if "All" in selected_categories:
            return available
        presets = self._category_format_presets()
        selected_formats: set[str] = set()
        for category in selected_categories:
            selected_formats.update(presets.get(category, set()))
        return selected_formats & available

    def _sync_formats_from_categories(self) -> None:
        if getattr(self, "_syncing_category_formats", False):
            return
        boxes = getattr(self, "format_boxes", {})
        if not boxes:
            return
        selected_formats = self._formats_for_selected_categories()
        self._syncing_category_formats = True
        try:
            for label, box in boxes.items():
                checked = label in selected_formats
                blocked = box.blockSignals(True)
                box.setChecked(checked)
                box.blockSignals(blocked)
                self._remember_filter_selection("format", label, checked)
            self._sync_all_types_from_children("format")
        finally:
            self._syncing_category_formats = False

    def _active_file_type_filter_group(self) -> str:
        if hasattr(self, "type_filter_tabs") and self.type_filter_tabs.currentIndex() == 1:
            return "format"
        return "category"

    def _selected_file_type_filter_labels(self) -> list[str]:
        group = self._active_file_type_filter_group()
        boxes, _master = self._boxes_for_all_types_group(group)
        labels = [label for label, box in boxes.items() if box.isChecked()]
        if boxes:
            return labels
        cached = getattr(self, "_filter_selection_cache", {}).get(group, {})
        return [label for label, checked in cached.items() if checked]

    def _selected_file_type_filter_parts(self) -> list[str]:
        group = self._active_file_type_filter_group()
        labels = self._selected_file_type_filter_labels()
        if not labels:
            return []
        if group == "format":
            return ["--fmt", ",".join(label.replace(" / ", ",") for label in labels)]
        category_values = {
            "Pictures": "images",
            "Documents": "documents",
            "Video": "videos",
            "Audio": "audio",
            "Archives": "archives",
            "All": "all",
        }
        selected = [category_values[label] for label in labels if label in category_values]
        if "all" in selected:
            selected = ["all"]
        return ["--cat", ",".join(selected)] if selected else []

    def _set_all_types_visibility(self, visible: bool) -> None:
        for name in ("category_all_types_box", "format_all_types_box"):
            box = getattr(self, name, None)
            if box is not None:
                box.setVisible(visible)
        self._relayout_filter_grid("category")
        self._relayout_filter_grid("format")

    def _set_all_types_state(self, group: str, checked: bool, *, force_children: bool) -> None:
        boxes, master = self._boxes_for_all_types_group(group)
        if master is None:
            return
        blocked = master.blockSignals(True)
        master.setChecked(checked)
        master.blockSignals(blocked)
        if force_children:
            for label, box in boxes.items():
                child_blocked = box.blockSignals(True)
                box.setChecked(checked)
                box.blockSignals(child_blocked)
                self._remember_filter_selection(group, label, checked)

    def _handle_all_types_toggled(self, group: str, checked: bool) -> None:
        boxes, master = self._boxes_for_all_types_group(group)
        if master is None or not master.isVisible():
            return
        for label, box in boxes.items():
            blocked = box.blockSignals(True)
            box.setChecked(checked)
            box.blockSignals(blocked)
            self._remember_filter_selection(group, label, checked)
        if group == "category":
            self._sync_formats_from_categories()
        self._refresh_command_preview()
        self._refresh_plan_status()

    def _sync_all_types_from_children(self, group: str) -> None:
        boxes, master = self._boxes_for_all_types_group(group)
        if master is None or not master.isVisible():
            return
        all_checked = bool(boxes) and all(box.isChecked() for box in boxes.values())
        blocked = master.blockSignals(True)
        master.setChecked(all_checked)
        master.blockSignals(blocked)

    def _relayout_filter_grid(self, group: str) -> None:
        if group == "category":
            layout = getattr(self, "category_layout", None)
            master = getattr(self, "category_all_types_box", None)
            boxes = getattr(self, "category_boxes", {})
        else:
            layout = getattr(self, "format_layout", None)
            master = getattr(self, "format_all_types_box", None)
            boxes = getattr(self, "format_boxes", {})
        if layout is None:
            return

        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                layout.removeWidget(widget)

        ordered = []
        if master is not None and master.isVisible():
            ordered.append(master)
        ordered.extend(boxes.values())
        for index, widget in enumerate(ordered):
            layout.addWidget(widget, index // 3, index % 3)

        for column in range(3):
            layout.setColumnStretch(column, 1)
        layout.setRowStretch((len(ordered) + 2) // 3, 1)

    @staticmethod
    def _default_format_selection():
        return {"jpg", "jpeg", "png", "gif", "tiff", "bmp", "webp", "heic", "pdf", "docx"}

    def _apply_default_filter_presets(self) -> None:
        default_categories = {"All"}
        for label, box in getattr(self, "category_boxes", {}).items():
            blocked = box.blockSignals(True)
            box.setChecked(label in default_categories)
            box.blockSignals(blocked)
            self._remember_filter_selection("category", label, label in default_categories)
        self._sync_formats_from_categories()

    @staticmethod
    def _available_carv_formats():
        fallback = [
            "jpg", "jpeg", "png", "gif", "tiff", "pdf", "docx", "bmp",
            "webp", "heic", "psd", "sqlite", "zip",
        ]
        try:
            result = subprocess.run(
                [str(app_runtime_root() / "carv"), "--list-formats"],
                cwd=str(app_runtime_root()), capture_output=True, text=True,
                timeout=10, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return fallback
        if result.returncode != 0:
            return fallback
        formats = []
        for line in result.stdout.splitlines():
            value = line.strip().lower().lstrip(".")
            if re.fullmatch(r"[a-z0-9][a-z0-9_+-]{0,15}", value) and value not in formats:
                formats.append(value)
        return formats or fallback


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Carv")
    app.setApplicationVersion(CARV_VERSION)
    if sys.platform.startswith("linux"):
        app.setDesktopFileName("Carv")
    app_icon = QIcon(WRENCH_ICON_PATH)
    if not app_icon.isNull():
        app.setWindowIcon(app_icon)
    app.setFont(QFont("Helvetica Neue" if sys.platform == "darwin" else "DejaVu Sans"))
    window = CarvGuiWindow()
    if not app_icon.isNull():
        window.setWindowIcon(app_icon)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Source: github.com/zeittresor

PyCache Cleaner GUI
Finds and deletes Python __pycache__ folders to reclaim disk space.

- Windows 10/11 friendly
- Works with PyQt6 (preferred) or PyQt5 (fallback)
- Scans selected roots (drives / user home)
- Shows count and estimated reclaimable size
"""

from __future__ import annotations

import os
import sys
import time
import shutil
import traceback
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict

# ---- Qt import (PyQt6 preferred, PyQt5 fallback) ----
QT6 = False
try:
    from PyQt6 import QtCore, QtGui, QtWidgets
    QT6 = True
except Exception:
    try:
        from PyQt5 import QtCore, QtGui, QtWidgets  # type: ignore
        QT6 = False
    except Exception as e:
        print("PyQt is not installed.\nInstall with:\n  pip install PyQt6\n(or: pip install PyQt5)\n")
        raise

Signal = QtCore.pyqtSignal


def _tr(s: str) -> str:
    """Identity translation helper (actual translation done via dict in UI)."""
    return s


def format_bytes(num: int) -> str:
    if num < 0:
        num = 0
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    n = float(num)
    for u in units:
        if n < 1024.0 or u == units[-1]:
            if u == "B":
                return f"{int(n)} {u}"
            return f"{n:.2f} {u}"
        n /= 1024.0
    return f"{n:.2f} PB"


def is_windows() -> bool:
    return os.name == "nt"


def list_windows_roots() -> List[str]:
    """Returns a list of drive roots, e.g. ['C:\\', 'D:\\']."""
    drives: List[str] = []
    if not is_windows():
        return [os.path.abspath(os.sep)]
    try:
        import ctypes
        import string
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i, letter in enumerate(string.ascii_uppercase):
            if bitmask & (1 << i):
                drives.append(f"{letter}:\\")
    except Exception:
        # fallback: brute-force
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            p = f"{letter}:\\"
            if os.path.exists(p):
                drives.append(p)
    return drives


def normcase(p: str) -> str:
    return os.path.normcase(os.path.normpath(p))


def is_reparse_point(path: str) -> bool:
    """Best-effort detection of Windows junctions/symlinks/reparse points."""
    if not is_windows():
        return os.path.islink(path)
    try:
        st = os.stat(path, follow_symlinks=False)
        attrs = getattr(st, "st_file_attributes", 0)
        FILE_ATTRIBUTE_REPARSE_POINT = 0x400
        return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
    except Exception:
        return os.path.islink(path)


@dataclass
class FoundItem:
    path: str
    size_bytes: int
    file_count: int


@dataclass
class ScanStats:
    scanned_dirs: int = 0
    found_dirs: int = 0
    found_files: int = 0
    found_size_bytes: int = 0
    errors: int = 0
    cancelled: bool = False
    elapsed_s: float = 0.0


@dataclass
class DeleteStats:
    requested: int = 0
    deleted: int = 0
    failed: int = 0
    freed_bytes: int = 0
    errors: int = 0
    cancelled: bool = False
    elapsed_s: float = 0.0


class ScanWorker(QtCore.QObject):
    found_item = Signal(object)  # FoundItem
    progress = Signal(dict)      # {current_path, scanned_dirs, found_dirs, found_size_bytes, errors}
    finished = Signal(object)    # ScanStats
    log = Signal(str)

    def __init__(self, roots: List[str], exclude_common: bool, follow_links: bool):
        super().__init__()
        self.roots = roots
        self.exclude_common = exclude_common
        self.follow_links = follow_links
        self._cancel = False

        # Common directories to skip when "exclude common/system" is enabled.
        # This is a pragmatic performance/safety trade-off and can be disabled.
        self.common_skip_names = {
            "windows",
            "program files",
            "program files (x86)",
            "$recycle.bin",
            "system volume information",
            "recovery",
            "msocache",
            "intel",
            "nvidia",
            "amd",
        }

    def cancel(self) -> None:
        self._cancel = True

    def _should_skip_dir(self, parent: str, name: str) -> bool:
        if not self.exclude_common:
            return False
        # Skip only at/near root? In practice: skip by name anywhere.
        return name.strip().lower() in self.common_skip_names

    def _dir_size(self, d: str) -> Tuple[int, int, int]:
        """Returns (size_bytes, file_count, errors) for directory d."""
        total = 0
        files = 0
        errors = 0
        stack = [d]
        while stack:
            if self._cancel:
                break
            cur = stack.pop()
            try:
                with os.scandir(cur) as it:
                    for entry in it:
                        try:
                            if entry.is_dir(follow_symlinks=self.follow_links):
                                # avoid loops / reparse points unless follow_links is enabled
                                if (not self.follow_links) and (entry.is_symlink() or is_reparse_point(entry.path)):
                                    continue
                                stack.append(entry.path)
                            else:
                                try:
                                    total += entry.stat(follow_symlinks=False).st_size
                                    files += 1
                                except Exception:
                                    errors += 1
                        except Exception:
                            errors += 1
            except Exception:
                errors += 1
        return total, files, errors

    @QtCore.pyqtSlot()
    def run(self) -> None:
        stats = ScanStats()
        t0 = time.time()

        # Use iterative DFS to avoid recursion depth issues.
        stack: List[str] = []
        for r in self.roots:
            r = os.path.abspath(r)
            if os.path.exists(r):
                stack.append(r)

        # De-duplicate roots (case-insensitive on Windows)
        seen = set()
        uniq_stack = []
        for p in stack:
            k = normcase(p) if is_windows() else p
            if k not in seen:
                seen.add(k)
                uniq_stack.append(p)
        stack = uniq_stack

        last_emit = 0.0
        while stack:
            if self._cancel:
                stats.cancelled = True
                break

            cur = stack.pop()
            stats.scanned_dirs += 1

            # Throttle progress updates
            now = time.time()
            if now - last_emit > 0.1:
                self.progress.emit({
                    "current_path": cur,
                    "scanned_dirs": stats.scanned_dirs,
                    "found_dirs": stats.found_dirs,
                    "found_size_bytes": stats.found_size_bytes,
                    "errors": stats.errors,
                })
                last_emit = now

            try:
                # Avoid loops / reparse points unless follow_links
                if (not self.follow_links) and (is_reparse_point(cur) or os.path.islink(cur)):
                    continue

                with os.scandir(cur) as it:
                    for entry in it:
                        if self._cancel:
                            stats.cancelled = True
                            break

                        try:
                            if entry.is_dir(follow_symlinks=self.follow_links):
                                name = entry.name

                                if name == "__pycache__":
                                    size_b, file_c, err = self._dir_size(entry.path)
                                    stats.errors += err
                                    stats.found_dirs += 1
                                    stats.found_files += file_c
                                    stats.found_size_bytes += size_b
                                    self.found_item.emit(FoundItem(entry.path, size_b, file_c))
                                else:
                                    if self._should_skip_dir(cur, name):
                                        continue
                                    # Avoid loops / reparse points unless follow_links is enabled
                                    if (not self.follow_links) and (entry.is_symlink() or is_reparse_point(entry.path)):
                                        continue
                                    stack.append(entry.path)
                        except PermissionError:
                            stats.errors += 1
                        except FileNotFoundError:
                            # Race: directory removed while scanning
                            stats.errors += 1
                        except OSError:
                            stats.errors += 1
                        except Exception:
                            stats.errors += 1
            except PermissionError:
                stats.errors += 1
            except FileNotFoundError:
                stats.errors += 1
            except OSError:
                stats.errors += 1
            except Exception:
                stats.errors += 1
                self.log.emit("Unexpected error while scanning:\n" + traceback.format_exc())

        stats.elapsed_s = max(0.0, time.time() - t0)
        # Final progress emit
        self.progress.emit({
            "current_path": "",
            "scanned_dirs": stats.scanned_dirs,
            "found_dirs": stats.found_dirs,
            "found_size_bytes": stats.found_size_bytes,
            "errors": stats.errors,
        })
        self.finished.emit(stats)


class DeleteWorker(QtCore.QObject):
    progress = Signal(dict)     # {current, idx, total, deleted, failed, freed_bytes, errors}
    finished = Signal(object)   # DeleteStats
    log = Signal(str)

    def __init__(self, items: List[FoundItem]):
        super().__init__()
        self.items = items
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    @QtCore.pyqtSlot()
    def run(self) -> None:
        stats = DeleteStats(requested=len(self.items))
        t0 = time.time()

        for i, it in enumerate(self.items, start=1):
            if self._cancel:
                stats.cancelled = True
                break

            self.progress.emit({
                "current": it.path,
                "idx": i,
                "total": len(self.items),
                "deleted": stats.deleted,
                "failed": stats.failed,
                "freed_bytes": stats.freed_bytes,
                "errors": stats.errors,
            })

            try:
                # Safety: only delete directories actually named __pycache__
                if os.path.basename(it.path) != "__pycache__":
                    stats.failed += 1
                    stats.errors += 1
                    self.log.emit(f"Skipped (safety): {it.path}")
                    continue

                shutil.rmtree(it.path)
                stats.deleted += 1
                stats.freed_bytes += max(0, int(it.size_bytes))
            except FileNotFoundError:
                # Already gone
                stats.failed += 1
            except PermissionError:
                stats.failed += 1
                stats.errors += 1
            except OSError:
                stats.failed += 1
                stats.errors += 1
            except Exception:
                stats.failed += 1
                stats.errors += 1
                self.log.emit("Unexpected error while deleting:\n" + traceback.format_exc())

        stats.elapsed_s = max(0.0, time.time() - t0)
        self.progress.emit({
            "current": "",
            "idx": len(self.items),
            "total": len(self.items),
            "deleted": stats.deleted,
            "failed": stats.failed,
            "freed_bytes": stats.freed_bytes,
            "errors": stats.errors,
        })
        self.finished.emit(stats)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PyCache Cleaner GUI")
        self.resize(980, 720)

        self._scan_thread: Optional[QtCore.QThread] = None
        self._scan_worker: Optional[ScanWorker] = None
        self._delete_thread: Optional[QtCore.QThread] = None
        self._delete_worker: Optional[DeleteWorker] = None

        self.found: List[FoundItem] = []

        self.lang = "en"
        self.strings: Dict[str, Dict[str, str]] = {
            "en": {
                "roots": "Scan roots",
                "options": "Options",
                "exclude_common": "Exclude common/system folders (faster)",
                "follow_links": "Follow symlinks/junctions (can be slow / loops)",
                "start_scan": "Start scan",
                "cancel": "Cancel",
                "results": "Results",
                "path": "Path",
                "size": "Size",
                "files": "Files",
                "summary": "Found: {dirs} folders • Reclaimable: {size} • Errors: {errors}",
                "scanning": "Scanning… {path}",
                "ready": "Ready.",
                "delete_selected": "Delete selected",
                "delete_all": "Delete all found",
                "export": "Export list…",
                "open_folder": "Open folder",
                "confirm_delete": "Delete {n} __pycache__ folders?\n\nThis only removes cached bytecode (.pyc). Python will recreate it if needed.",
                "yes": "Yes",
                "no": "No",
                "scan_done": "Scan done in {sec:.1f}s • Scanned dirs: {scanned} • Found: {found}",
                "delete_done": "Delete done in {sec:.1f}s • Deleted: {deleted} • Failed: {failed} • Freed: {size}",
                "nothing_selected": "No rows selected.",
                "nothing_found": "Nothing found.",
                "busy": "Busy",
                "busy_msg": "An operation is already running.",
            },
            "de": {
                "roots": "Scan-Pfade",
                "options": "Optionen",
                "exclude_common": "Übliche/System-Ordner überspringen (schneller)",
                "follow_links": "Symlinks/Junctions folgen (kann langsam sein / Schleifen)",
                "start_scan": "Scan starten",
                "cancel": "Abbrechen",
                "results": "Ergebnisse",
                "path": "Pfad",
                "size": "Größe",
                "files": "Dateien",
                "summary": "Gefunden: {dirs} Ordner • Freigebbar: {size} • Fehler: {errors}",
                "scanning": "Scanne… {path}",
                "ready": "Bereit.",
                "delete_selected": "Auswahl löschen",
                "delete_all": "Alle gefundenen löschen",
                "export": "Liste exportieren…",
                "open_folder": "Ordner öffnen",
                "confirm_delete": "{n} __pycache__-Ordner löschen?\n\nEs werden nur Bytecode-Caches (.pyc) entfernt. Python erstellt sie bei Bedarf neu.",
                "yes": "Ja",
                "no": "Nein",
                "scan_done": "Scan fertig in {sec:.1f}s • Gescannte Ordner: {scanned} • Gefunden: {found}",
                "delete_done": "Löschen fertig in {sec:.1f}s • Gelöscht: {deleted} • Fehlgeschlagen: {failed} • Frei: {size}",
                "nothing_selected": "Keine Zeilen ausgewählt.",
                "nothing_found": "Nichts gefunden.",
                "busy": "Beschäftigt",
                "busy_msg": "Es läuft bereits eine Aktion.",
            },
        }

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        root_layout = QtWidgets.QVBoxLayout(central)

        # ---- Top row: language ----
        top_row = QtWidgets.QHBoxLayout()
        root_layout.addLayout(top_row)

        top_row.addWidget(QtWidgets.QLabel("Language / Sprache:"))
        self.lang_combo = QtWidgets.QComboBox()
        self.lang_combo.addItem("English", "en")
        self.lang_combo.addItem("Deutsch", "de")
        self.lang_combo.currentIndexChanged.connect(self.on_language_changed)
        top_row.addWidget(self.lang_combo)
        top_row.addStretch(1)

        # ---- Roots + Options ----
        roots_group = QtWidgets.QGroupBox()
        root_layout.addWidget(roots_group)
        roots_layout = QtWidgets.QGridLayout(roots_group)

        self.roots_group_label = QtWidgets.QLabel()
        roots_layout.addWidget(self.roots_group_label, 0, 0, 1, 2)

        self.roots_list = QtWidgets.QListWidget()
        self.roots_list.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.NoSelection
                                         if QT6 else QtWidgets.QAbstractItemView.NoSelection)
        roots_layout.addWidget(self.roots_list, 1, 0, 4, 1)

        opts_box = QtWidgets.QGroupBox()
        self.opts_title = QtWidgets.QLabel()
        opts_layout = QtWidgets.QVBoxLayout(opts_box)
        opts_layout.addWidget(self.opts_title)

        self.cb_exclude_common = QtWidgets.QCheckBox()
        self.cb_exclude_common.setChecked(True)
        opts_layout.addWidget(self.cb_exclude_common)

        self.cb_follow_links = QtWidgets.QCheckBox()
        self.cb_follow_links.setChecked(False)
        opts_layout.addWidget(self.cb_follow_links)

        opts_layout.addStretch(1)

        roots_layout.addWidget(opts_box, 1, 1, 3, 1)

        btn_row = QtWidgets.QHBoxLayout()
        self.btn_scan = QtWidgets.QPushButton()
        self.btn_cancel = QtWidgets.QPushButton()
        self.btn_cancel.setEnabled(False)
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_cancel.clicked.connect(self.cancel_operation)
        btn_row.addWidget(self.btn_scan)
        btn_row.addWidget(self.btn_cancel)
        btn_row.addStretch(1)
        roots_layout.addLayout(btn_row, 4, 1, 1, 1)

        # ---- Progress ----
        prog_row = QtWidgets.QHBoxLayout()
        root_layout.addLayout(prog_row)
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.progress_label = QtWidgets.QLabel()
        prog_row.addWidget(self.progress_bar, 1)
        prog_row.addWidget(self.progress_label, 2)

        # ---- Results table ----
        results_group = QtWidgets.QGroupBox()
        root_layout.addWidget(results_group, 1)
        results_layout = QtWidgets.QVBoxLayout(results_group)

        self.results_title = QtWidgets.QLabel()
        results_layout.addWidget(self.results_title)

        self.table = QtWidgets.QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Path", "Size", "Files"])
        self.table.horizontalHeader().setStretchLastSection(True)
        try:
            self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
            self.table.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        except Exception:
            self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
            self.table.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
                                  if QT6 else QtWidgets.QAbstractItemView.NoEditTriggers)
        results_layout.addWidget(self.table, 1)

        actions_row = QtWidgets.QHBoxLayout()
        self.btn_delete_selected = QtWidgets.QPushButton()
        self.btn_delete_all = QtWidgets.QPushButton()
        self.btn_export = QtWidgets.QPushButton()
        self.btn_open = QtWidgets.QPushButton()
        self.btn_delete_selected.clicked.connect(self.delete_selected)
        self.btn_delete_all.clicked.connect(self.delete_all)
        self.btn_export.clicked.connect(self.export_list)
        self.btn_open.clicked.connect(self.open_selected_folder)
        actions_row.addWidget(self.btn_delete_selected)
        actions_row.addWidget(self.btn_delete_all)
        actions_row.addWidget(self.btn_export)
        actions_row.addWidget(self.btn_open)
        actions_row.addStretch(1)
        results_layout.addLayout(actions_row)

        # ---- Summary + log ----
        self.summary_label = QtWidgets.QLabel()
        root_layout.addWidget(self.summary_label)

        self.log_box = QtWidgets.QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMinimumHeight(110)
        root_layout.addWidget(self.log_box)

        self._populate_roots()
        self._apply_language()

    def t(self, key: str, **kwargs) -> str:
        s = self.strings.get(self.lang, self.strings["en"]).get(key, key)
        if kwargs:
            try:
                return s.format(**kwargs)
            except Exception:
                return s
        return s

    def _apply_language(self) -> None:
        self.roots_group_label.setText(f"<b>{self.t('roots')}</b>")
        self.opts_title.setText(f"<b>{self.t('options')}</b>")
        self.cb_exclude_common.setText(self.t("exclude_common"))
        self.cb_follow_links.setText(self.t("follow_links"))
        self.btn_scan.setText(self.t("start_scan"))
        self.btn_cancel.setText(self.t("cancel"))
        self.results_title.setText(f"<b>{self.t('results')}</b>")
        self.table.setHorizontalHeaderLabels([self.t("path"), self.t("size"), self.t("files")])
        self.btn_delete_selected.setText(self.t("delete_selected"))
        self.btn_delete_all.setText(self.t("delete_all"))
        self.btn_export.setText(self.t("export"))
        self.btn_open.setText(self.t("open_folder"))
        self.progress_label.setText(self.t("ready"))
        self._update_summary(0, 0, 0)

    def on_language_changed(self) -> None:
        self.lang = self.lang_combo.currentData() or "en"
        self._apply_language()

    def _populate_roots(self) -> None:
        self.roots_list.clear()

        # User home (useful default)
        home = os.path.expanduser("~")
        if home and os.path.exists(home):
            item = QtWidgets.QListWidgetItem(f"Home: {home}")
            item.setFlags(item.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable
                          if QT6 else item.flags() | QtCore.Qt.ItemIsUserCheckable)
            item.setCheckState(QtCore.Qt.CheckState.Checked if QT6 else QtCore.Qt.Checked)
            item.setData(QtCore.Qt.ItemDataRole.UserRole if QT6 else QtCore.Qt.UserRole, home)
            self.roots_list.addItem(item)

        for d in list_windows_roots():
            item = QtWidgets.QListWidgetItem(d)
            item.setFlags(item.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable
                          if QT6 else item.flags() | QtCore.Qt.ItemIsUserCheckable)
            # Leave drives unchecked by default (to avoid hours-long scans)
            item.setCheckState(QtCore.Qt.CheckState.Unchecked if QT6 else QtCore.Qt.Unchecked)
            item.setData(QtCore.Qt.ItemDataRole.UserRole if QT6 else QtCore.Qt.UserRole, d)
            self.roots_list.addItem(item)

    def _selected_roots(self) -> List[str]:
        roots: List[str] = []
        for i in range(self.roots_list.count()):
            it = self.roots_list.item(i)
            state = it.checkState()
            checked = (state == (QtCore.Qt.CheckState.Checked if QT6 else QtCore.Qt.Checked))
            if checked:
                roots.append(it.data(QtCore.Qt.ItemDataRole.UserRole if QT6 else QtCore.Qt.UserRole))
        # If user unchecked everything, fall back to home (if exists)
        if not roots:
            home = os.path.expanduser("~")
            if home and os.path.exists(home):
                roots = [home]
        return roots

    def _busy(self) -> bool:
        return (self._scan_thread is not None) or (self._delete_thread is not None)

    def _msgbox_yesno(self, title: str, text: str) -> bool:
        m = QtWidgets.QMessageBox(self)
        m.setWindowTitle(title)
        m.setText(text)
        try:
            m.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No)
            m.setDefaultButton(QtWidgets.QMessageBox.StandardButton.No)
            res = m.exec()
            return res == int(QtWidgets.QMessageBox.StandardButton.Yes)
        except Exception:
            m.setStandardButtons(QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
            m.setDefaultButton(QtWidgets.QMessageBox.No)
            res = m.exec_() if hasattr(m, "exec_") else m.exec()
            return res == QtWidgets.QMessageBox.Yes

    def _msgbox_info(self, title: str, text: str) -> None:
        QtWidgets.QMessageBox.information(self, title, text)

    def _msgbox_warn(self, title: str, text: str) -> None:
        QtWidgets.QMessageBox.warning(self, title, text)

    def _update_summary(self, dirs: int, size_bytes: int, errors: int) -> None:
        self.summary_label.setText(self.t("summary", dirs=dirs, size=format_bytes(size_bytes), errors=errors))

    def _append_log(self, s: str) -> None:
        self.log_box.append(s.rstrip())

    def clear_results(self) -> None:
        self.found.clear()
        self.table.setRowCount(0)
        self.log_box.clear()
        self._update_summary(0, 0, 0)

    def start_scan(self) -> None:
        if self._busy():
            self._msgbox_warn(self.t("busy"), self.t("busy_msg"))
            return

        self.clear_results()
        roots = self._selected_roots()

        exclude_common = self.cb_exclude_common.isChecked()
        follow_links = self.cb_follow_links.isChecked()

        self._scan_thread = QtCore.QThread()
        self._scan_worker = ScanWorker(roots=roots, exclude_common=exclude_common, follow_links=follow_links)
        self._scan_worker.moveToThread(self._scan_thread)

        self._scan_thread.started.connect(self._scan_worker.run)
        self._scan_worker.found_item.connect(self.on_found_item)
        self._scan_worker.progress.connect(self.on_scan_progress)
        self._scan_worker.finished.connect(self.on_scan_finished)
        self._scan_worker.log.connect(self._append_log)

        self._scan_thread.start()

        self.btn_scan.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress_bar.setRange(0, 0)  # busy indicator
        self.progress_label.setText(self.t("scanning", path=""))

    def on_found_item(self, item: FoundItem) -> None:
        self.found.append(item)
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(item.path))
        self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(format_bytes(item.size_bytes)))
        self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(str(item.file_count)))

        # Keep it snappy when many rows are added
        if row % 200 == 0:
            QtWidgets.QApplication.processEvents()

    def on_scan_progress(self, info: dict) -> None:
        cur = info.get("current_path", "")
        found_dirs = int(info.get("found_dirs", 0))
        found_size = int(info.get("found_size_bytes", 0))
        errors = int(info.get("errors", 0))
        if cur:
            self.progress_label.setText(self.t("scanning", path=cur))
        self._update_summary(found_dirs, found_size, errors)

    def on_scan_finished(self, stats: ScanStats) -> None:
        # Tear down thread/worker
        if self._scan_thread is not None:
            self._scan_thread.quit()
            self._scan_thread.wait(1500)
        self._scan_thread = None
        self._scan_worker = None

        self.btn_scan.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(1)
        self.progress_label.setText(self.t("ready"))

        self._append_log(self.t("scan_done", sec=stats.elapsed_s, scanned=stats.scanned_dirs, found=stats.found_dirs))
        if stats.cancelled:
            self._append_log("Cancelled.")

    def cancel_operation(self) -> None:
        if self._scan_worker is not None:
            self._scan_worker.cancel()
        if self._delete_worker is not None:
            self._delete_worker.cancel()

    def _selected_items(self) -> List[FoundItem]:
        rows = {idx.row() for idx in self.table.selectionModel().selectedRows()}
        if not rows:
            return []
        items = []
        for r in sorted(rows):
            if 0 <= r < len(self.found):
                items.append(self.found[r])
        return items

    def delete_selected(self) -> None:
        if self._busy():
            self._msgbox_warn(self.t("busy"), self.t("busy_msg"))
            return
        items = self._selected_items()
        if not items:
            self._msgbox_info("Info", self.t("nothing_selected"))
            return
        self._start_delete(items)

    def delete_all(self) -> None:
        if self._busy():
            self._msgbox_warn(self.t("busy"), self.t("busy_msg"))
            return
        if not self.found:
            self._msgbox_info("Info", self.t("nothing_found"))
            return
        self._start_delete(list(self.found))

    def _start_delete(self, items: List[FoundItem]) -> None:
        if not self._msgbox_yesno("Confirm", self.t("confirm_delete", n=len(items))):
            return

        self._delete_thread = QtCore.QThread()
        self._delete_worker = DeleteWorker(items=items)
        self._delete_worker.moveToThread(self._delete_thread)

        self._delete_thread.started.connect(self._delete_worker.run)
        self._delete_worker.progress.connect(self.on_delete_progress)
        self._delete_worker.finished.connect(self.on_delete_finished)
        self._delete_worker.log.connect(self._append_log)

        self._delete_thread.start()

        self.btn_scan.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress_bar.setRange(0, 0)
        self.progress_label.setText("Deleting…")

    def on_delete_progress(self, info: dict) -> None:
        cur = info.get("current", "")
        deleted = int(info.get("deleted", 0))
        failed = int(info.get("failed", 0))
        freed = int(info.get("freed_bytes", 0))
        errors = int(info.get("errors", 0))
        if cur:
            self.progress_label.setText(f"Deleting… {cur}")
        # summary: show current freed estimate in place of reclaimable
        self.summary_label.setText(
            f"Deleted: {deleted} • Failed: {failed} • Freed: {format_bytes(freed)} • Errors: {errors}"
        )

    def on_delete_finished(self, stats: DeleteStats) -> None:
        if self._delete_thread is not None:
            self._delete_thread.quit()
            self._delete_thread.wait(1500)
        self._delete_thread = None
        self._delete_worker = None

        # Remove deleted entries from list/table (best-effort)
        remaining: List[FoundItem] = []
        deleted_paths = set()
        # We can't know exactly which failed from stats alone; remove any that no longer exists
        for it in self.found:
            if os.path.exists(it.path):
                remaining.append(it)
            else:
                deleted_paths.add(it.path)
        self.found = remaining
        self._rebuild_table()

        self.btn_scan.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(1)
        self.progress_label.setText(self.t("ready"))

        self._append_log(self.t("delete_done", sec=stats.elapsed_s, deleted=stats.deleted,
                                failed=stats.failed, size=format_bytes(stats.freed_bytes)))
        if stats.cancelled:
            self._append_log("Cancelled.")

        # Update summary with remaining reclaimable size
        rem_size = sum(it.size_bytes for it in self.found)
        self._update_summary(len(self.found), rem_size, 0)

    def _rebuild_table(self) -> None:
        self.table.setRowCount(0)
        for it in self.found:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(it.path))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(format_bytes(it.size_bytes)))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(str(it.file_count)))

    def export_list(self) -> None:
        if not self.found:
            self._msgbox_info("Info", self.t("nothing_found"))
            return

        default_name = "pycache_list.txt"
        if QT6:
            path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export", default_name, "Text files (*.txt);;All files (*.*)")
        else:
            path = QtWidgets.QFileDialog.getSaveFileName(self, "Export", default_name, "Text files (*.txt);;All files (*.*)")[0]

        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                total = 0
                for it in self.found:
                    total += it.size_bytes
                    f.write(f"{it.path}\t{it.size_bytes}\t{it.file_count}\n")
                f.write(f"\nTOTAL\t{total}\n")
            self._append_log(f"Exported: {path}")
        except Exception:
            self._append_log("Failed to export:\n" + traceback.format_exc())

    def open_selected_folder(self) -> None:
        items = self._selected_items()
        if not items:
            self._msgbox_info("Info", self.t("nothing_selected"))
            return
        # Open the parent folder of the first selected __pycache__
        p = os.path.dirname(items[0].path)
        try:
            if is_windows():
                os.startfile(p)  # type: ignore[attr-defined]
            else:
                QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(p))
        except Exception:
            self._append_log("Failed to open folder:\n" + traceback.format_exc())


def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    if hasattr(app, "exec"):
        return app.exec()  # PyQt6
    return app.exec_()     # PyQt5


if __name__ == "__main__":
    raise SystemExit(main())

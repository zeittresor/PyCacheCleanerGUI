#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Source: https://github.com/zeittresor/PyCacheCleanerGUI

PyCache Cleaner GUI (PyQt6 only)

- Finds Python __pycache__ folders and can delete them.
- Shows found folder count and reclaimable size (estimated).
- Designed to handle very large result sets (batch signals + QAbstractTableModel).
"""

from __future__ import annotations

import os
import sys
import time
import shutil
import traceback
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict, Any

from PyQt6 import QtCore, QtGui, QtWidgets

Signal = QtCore.pyqtSignal


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
    if not is_windows():
        return [os.path.abspath(os.sep)]
    drives: List[str] = []
    try:
        import ctypes
        import string
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i, letter in enumerate(string.ascii_uppercase):
            if bitmask & (1 << i):
                drives.append(f"{letter}:\\")
    except Exception:
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            p = f"{letter}:\\"
            if os.path.exists(p):
                drives.append(p)
    return drives


def normcase(p: str) -> str:
    return os.path.normcase(os.path.normpath(p))


def is_reparse_point(path: str) -> bool:
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


class FoundModel(QtCore.QAbstractTableModel):
    COLS = ("Path", "Size", "Files")

    def __init__(self) -> None:
        super().__init__()
        self.items: List[FoundItem] = []

    def clear(self) -> None:
        self.beginResetModel()
        self.items.clear()
        self.endResetModel()

    def add_items(self, new_items: List[FoundItem]) -> None:
        if not new_items:
            return
        start = len(self.items)
        end = start + len(new_items) - 1
        self.beginInsertRows(QtCore.QModelIndex(), start, end)
        self.items.extend(new_items)
        self.endInsertRows()

    def rowCount(self, parent: QtCore.QModelIndex = QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.items)

    def columnCount(self, parent: QtCore.QModelIndex = QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else 3

    def headerData(self, section: int, orientation: QtCore.Qt.Orientation, role: int = 0) -> Any:
        if role != int(QtCore.Qt.ItemDataRole.DisplayRole):
            return None
        if orientation == QtCore.Qt.Orientation.Horizontal:
            if 0 <= section < 3:
                return self.COLS[section]
        return str(section + 1)

    def data(self, index: QtCore.QModelIndex, role: int = 0) -> Any:
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        if row < 0 or row >= len(self.items):
            return None
        it = self.items[row]
        if role == int(QtCore.Qt.ItemDataRole.DisplayRole):
            if col == 0:
                return it.path
            if col == 1:
                return format_bytes(it.size_bytes)
            if col == 2:
                return str(it.file_count)
        if role == int(QtCore.Qt.ItemDataRole.ToolTipRole):
            return it.path
        return None

    def get_items_by_rows(self, rows: List[int]) -> List[FoundItem]:
        out: List[FoundItem] = []
        for r in rows:
            if 0 <= r < len(self.items):
                out.append(self.items[r])
        return out

    def total_size(self) -> int:
        return sum(i.size_bytes for i in self.items)


class ScanWorker(QtCore.QObject):
    batch_found = Signal(list)   # List[FoundItem]
    progress = Signal(dict)      # {current_path, scanned_dirs, found_dirs, found_size_bytes, errors}
    finished = Signal(object)    # ScanStats
    log = Signal(str)

    def __init__(self, roots: List[str], exclude_common: bool, follow_links: bool, calc_sizes: bool, batch_size: int = 300):
        super().__init__()
        self.roots = roots
        self.exclude_common = exclude_common
        self.follow_links = follow_links
        self.calc_sizes = calc_sizes
        self.batch_size = max(10, int(batch_size))
        self._cancel = False

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

    def _should_skip_dir(self, name: str) -> bool:
        if not self.exclude_common:
            return False
        return name.strip().lower() in self.common_skip_names

    def _dir_size(self, d: str) -> Tuple[int, int, int]:
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

        # Prepare unique roots (case-insensitive on Windows)
        raw_roots: List[str] = []
        for r in self.roots:
            r = os.path.abspath(r)
            if os.path.exists(r):
                raw_roots.append(r)

        seen_roots = set()
        roots: List[str] = []
        for p in raw_roots:
            k = normcase(p) if is_windows() else p
            if k not in seen_roots:
                seen_roots.add(k)
                roots.append(p)

        if not roots:
            stats.elapsed_s = 0.0
            self.finished.emit(stats)
            return

        # Global de-duplication of directories across all roots (prevents double scanning if roots overlap)
        seen_dirs = set()

        last_emit = 0.0
        batch: List[FoundItem] = []

        total_roots = len(roots)

        for root_idx, root_path in enumerate(roots, start=1):
            if self._cancel:
                stats.cancelled = True
                break

            self.log.emit(f"== Root {root_idx}/{total_roots}: {root_path} ==")

            # Depth-first traversal inside this root
            stack: List[str] = [root_path]

            while stack:
                if self._cancel:
                    stats.cancelled = True
                    break

                cur = stack.pop()

                # De-duplicate across all roots
                key = normcase(cur) if is_windows() else cur
                if key in seen_dirs:
                    continue
                seen_dirs.add(key)

                stats.scanned_dirs += 1

                now = time.time()
                if now - last_emit > 0.1:
                    self.progress.emit({
                        "current_path": f"[{root_idx}/{total_roots}] {cur}",
                        "scanned_dirs": stats.scanned_dirs,
                        "found_dirs": stats.found_dirs,
                        "found_size_bytes": stats.found_size_bytes,
                        "errors": stats.errors,
                    })
                    last_emit = now

                try:
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
                                        if self.calc_sizes:
                                            size_b, file_c, err = self._dir_size(entry.path)
                                        else:
                                            size_b, file_c, err = 0, 0, 0

                                        stats.errors += err
                                        stats.found_dirs += 1
                                        stats.found_files += file_c
                                        stats.found_size_bytes += size_b

                                        batch.append(FoundItem(entry.path, size_b, file_c))
                                        if len(batch) >= self.batch_size:
                                            self.batch_found.emit(batch)
                                            batch = []
                                    else:
                                        if self._should_skip_dir(name):
                                            continue
                                        if (not self.follow_links) and (entry.is_symlink() or is_reparse_point(entry.path)):
                                            continue
                                        stack.append(entry.path)
                            except Exception:
                                stats.errors += 1
                except Exception:
                    stats.errors += 1

            if stats.cancelled:
                break

        if batch:
            self.batch_found.emit(batch)

        stats.elapsed_s = max(0.0, time.time() - t0)
        self.progress.emit({
            "current_path": "",
            "scanned_dirs": stats.scanned_dirs,
            "found_dirs": stats.found_dirs,
            "found_size_bytes": stats.found_size_bytes,
            "errors": stats.errors,
        })
        self.finished.emit(stats)
class DeleteWorker(QtCore.QObject):
    progress = Signal(dict)
    finished = Signal(object)
    log = Signal(str)

    def __init__(self, items: List[FoundItem], recalc_size: bool):
        super().__init__()
        self.items = items
        self.recalc_size = recalc_size
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def _dir_size_quick(self, d: str) -> int:
        total = 0
        stack = [d]
        while stack:
            if self._cancel:
                break
            cur = stack.pop()
            try:
                with os.scandir(cur) as it:
                    for entry in it:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if entry.is_symlink() or is_reparse_point(entry.path):
                                    continue
                                stack.append(entry.path)
                            else:
                                try:
                                    total += entry.stat(follow_symlinks=False).st_size
                                except Exception:
                                    pass
                        except Exception:
                            pass
            except Exception:
                pass
        return total

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
                if os.path.basename(it.path) != "__pycache__":
                    stats.failed += 1
                    stats.errors += 1
                    self.log.emit(f"Skipped (safety): {it.path}")
                    continue

                size_before = it.size_bytes
                if self.recalc_size or size_before <= 0:
                    size_before = self._dir_size_quick(it.path)

                shutil.rmtree(it.path)
                stats.deleted += 1
                stats.freed_bytes += max(0, int(size_before))
            except FileNotFoundError:
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
        self.setWindowTitle("PyCache Cleaner GUI (PyQt6)")
        self.resize(1020, 740)

        self._scan_thread: Optional[QtCore.QThread] = None
        self._scan_worker: Optional[ScanWorker] = None
        self._delete_thread: Optional[QtCore.QThread] = None
        self._delete_worker: Optional[DeleteWorker] = None

        self.lang = "de"
        self.strings: Dict[str, Dict[str, str]] = {
            "de": {
                "roots": "Scan-Pfade (Checkbox = aktiv)",
                "options": "Optionen",
                "exclude_common": "Übliche/System-Ordner überspringen (schneller)",
                "follow_links": "Symlinks/Junctions folgen (kann langsam sein / Schleifen)",
                "calc_sizes": "Größen während Scan berechnen (genauer, aber langsamer)",
                "recalc_before_delete": "Vor dem Löschen Größe neu berechnen (genauere Freigabe-Anzeige)",
                "start_scan": "Scan starten",
                "cancel": "Abbrechen",
                "results": "Ergebnisse",
                "summary": "Gefunden: {dirs} • Freigebbar: {size} • Fehler: {errors} • Gescannt: {scanned}",
                "scanning": "Scanne… {path}",
                "ready": "Bereit.",
                "delete_selected": "Auswahl löschen",
                "delete_all": "Alle gefundenen löschen",
                "export": "Liste exportieren…",
                "open_folder": "Ordner öffnen",
                "add_root": "Ordner hinzufügen…",
                "remove_root": "Entfernen",
                "confirm_delete": "{n} __pycache__-Ordner löschen?\n\nEs werden nur Bytecode-Caches (.pyc) entfernt. Python erstellt sie bei Bedarf neu.",
                "busy": "Beschäftigt",
                "busy_msg": "Es läuft bereits eine Aktion.",
                "nothing_selected": "Keine Zeilen ausgewählt.",
                "nothing_found": "Nichts gefunden.",
                "scan_done": "Scan fertig in {sec:.1f}s • Gescannte Ordner: {scanned} • Gefunden: {found}",
                "delete_done": "Löschen fertig in {sec:.1f}s • Gelöscht: {deleted} • Fehlgeschlagen: {failed} • Frei: {size}",
            },
            "en": {
                "roots": "Scan roots (checkbox = enabled)",
                "options": "Options",
                "exclude_common": "Exclude common/system folders (faster)",
                "follow_links": "Follow symlinks/junctions (can be slow / loops)",
                "calc_sizes": "Calculate sizes during scan (accurate, slower)",
                "recalc_before_delete": "Recalculate size before delete (more accurate freed display)",
                "start_scan": "Start scan",
                "cancel": "Cancel",
                "results": "Results",
                "summary": "Found: {dirs} • Reclaimable: {size} • Errors: {errors} • Scanned: {scanned}",
                "scanning": "Scanning… {path}",
                "ready": "Ready.",
                "delete_selected": "Delete selected",
                "delete_all": "Delete all found",
                "export": "Export list…",
                "open_folder": "Open folder",
                "add_root": "Add folder…",
                "remove_root": "Remove",
                "confirm_delete": "Delete {n} __pycache__ folders?\n\nThis only removes cached bytecode (.pyc). Python will recreate it if needed.",
                "busy": "Busy",
                "busy_msg": "An operation is already running.",
                "nothing_selected": "No rows selected.",
                "nothing_found": "Nothing found.",
                "scan_done": "Scan done in {sec:.1f}s • Scanned dirs: {scanned} • Found: {found}",
                "delete_done": "Delete done in {sec:.1f}s • Deleted: {deleted} • Failed: {failed} • Freed: {size}",
            },
        }

        self.model = FoundModel()

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        root = QtWidgets.QVBoxLayout(central)

        top = QtWidgets.QHBoxLayout()
        root.addLayout(top)
        top.addWidget(QtWidgets.QLabel("Language / Sprache:"))
        self.lang_combo = QtWidgets.QComboBox()
        self.lang_combo.addItem("Deutsch", "de")
        self.lang_combo.addItem("English", "en")
        self.lang_combo.currentIndexChanged.connect(self._on_lang_change)
        top.addWidget(self.lang_combo)
        top.addStretch(1)

        roots_group = QtWidgets.QGroupBox()
        root.addWidget(roots_group)
        rg = QtWidgets.QGridLayout(roots_group)

        self.lbl_roots = QtWidgets.QLabel()
        rg.addWidget(self.lbl_roots, 0, 0, 1, 3)

        self.roots_list = QtWidgets.QListWidget()
        self.roots_list.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        rg.addWidget(self.roots_list, 1, 0, 4, 2)

        btns = QtWidgets.QVBoxLayout()
        self.btn_add_root = QtWidgets.QPushButton()
        self.btn_remove_root = QtWidgets.QPushButton()
        self.btn_add_root.clicked.connect(self.add_root)
        self.btn_remove_root.clicked.connect(self.remove_selected_roots)
        btns.addWidget(self.btn_add_root)
        btns.addWidget(self.btn_remove_root)
        btns.addStretch(1)
        rg.addLayout(btns, 1, 2, 2, 1)

        opts = QtWidgets.QGroupBox()
        rg.addWidget(opts, 3, 2, 2, 1)
        ol = QtWidgets.QVBoxLayout(opts)
        self.lbl_opts = QtWidgets.QLabel()
        ol.addWidget(self.lbl_opts)
        self.cb_exclude = QtWidgets.QCheckBox()
        self.cb_exclude.setChecked(True)
        ol.addWidget(self.cb_exclude)
        self.cb_follow = QtWidgets.QCheckBox()
        self.cb_follow.setChecked(False)
        ol.addWidget(self.cb_follow)
        self.cb_calc_sizes = QtWidgets.QCheckBox()
        self.cb_calc_sizes.setChecked(True)
        ol.addWidget(self.cb_calc_sizes)
        self.cb_recalc_del = QtWidgets.QCheckBox()
        self.cb_recalc_del.setChecked(True)
        ol.addWidget(self.cb_recalc_del)
        ol.addStretch(1)

        scan_row = QtWidgets.QHBoxLayout()
        root.addLayout(scan_row)
        self.btn_scan = QtWidgets.QPushButton()
        self.btn_cancel = QtWidgets.QPushButton()
        self.btn_cancel.setEnabled(False)
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_cancel.clicked.connect(self.cancel_operation)
        scan_row.addWidget(self.btn_scan)
        scan_row.addWidget(self.btn_cancel)
        scan_row.addStretch(1)

        pr = QtWidgets.QHBoxLayout()
        root.addLayout(pr)
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.progress_label = QtWidgets.QLabel()
        pr.addWidget(self.progress_bar, 1)
        pr.addWidget(self.progress_label, 2)

        results_group = QtWidgets.QGroupBox()
        root.addWidget(results_group, 1)
        rl = QtWidgets.QVBoxLayout(results_group)
        self.lbl_results = QtWidgets.QLabel()
        rl.addWidget(self.lbl_results)

        self.view = QtWidgets.QTableView()
        self.view.setModel(self.model)
        self.view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.view.setAlternatingRowColors(True)
        self.view.setSortingEnabled(False)
        self.view.horizontalHeader().setStretchLastSection(True)
        self.view.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        rl.addWidget(self.view, 1)

        actions = QtWidgets.QHBoxLayout()
        self.btn_delete_selected = QtWidgets.QPushButton()
        self.btn_delete_all = QtWidgets.QPushButton()
        self.btn_export = QtWidgets.QPushButton()
        self.btn_open = QtWidgets.QPushButton()
        self.btn_delete_selected.clicked.connect(self.delete_selected)
        self.btn_delete_all.clicked.connect(self.delete_all)
        self.btn_export.clicked.connect(self.export_list)
        self.btn_open.clicked.connect(self.open_selected_folder)
        actions.addWidget(self.btn_delete_selected)
        actions.addWidget(self.btn_delete_all)
        actions.addWidget(self.btn_export)
        actions.addWidget(self.btn_open)
        actions.addStretch(1)
        rl.addLayout(actions)

        self.summary_label = QtWidgets.QLabel()
        root.addWidget(self.summary_label)

        self.log_box = QtWidgets.QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMinimumHeight(120)
        root.addWidget(self.log_box)

        self._populate_default_roots()
        self._apply_language()
        self._update_summary(0, 0, 0, 0)

    def t(self, k: str, **kwargs) -> str:
        s = self.strings.get(self.lang, self.strings["en"]).get(k, k)
        if kwargs:
            try:
                return s.format(**kwargs)
            except Exception:
                return s
        return s

    def _on_lang_change(self) -> None:
        self.lang = self.lang_combo.currentData() or "en"
        self._apply_language()
        self._update_summary(len(self.model.items), self.model.total_size(), 0, 0)

    def _apply_language(self) -> None:
        self.lbl_roots.setText(f"<b>{self.t('roots')}</b>")
        self.lbl_opts.setText(f"<b>{self.t('options')}</b>")
        self.cb_exclude.setText(self.t("exclude_common"))
        self.cb_follow.setText(self.t("follow_links"))
        self.cb_calc_sizes.setText(self.t("calc_sizes"))
        self.cb_recalc_del.setText(self.t("recalc_before_delete"))
        self.btn_scan.setText(self.t("start_scan"))
        self.btn_cancel.setText(self.t("cancel"))
        self.lbl_results.setText(f"<b>{self.t('results')}</b>")
        self.btn_delete_selected.setText(self.t("delete_selected"))
        self.btn_delete_all.setText(self.t("delete_all"))
        self.btn_export.setText(self.t("export"))
        self.btn_open.setText(self.t("open_folder"))
        self.btn_add_root.setText(self.t("add_root"))
        self.btn_remove_root.setText(self.t("remove_root"))
        self.progress_label.setText(self.t("ready"))

        self.model.headerDataChanged.emit(QtCore.Qt.Orientation.Horizontal, 0, 2)

    def _append_log(self, s: str) -> None:
        self.log_box.append(s.rstrip())

    def _busy(self) -> bool:
        return (self._scan_thread is not None) or (self._delete_thread is not None)

    def _msg_warn(self, title: str, text: str) -> None:
        QtWidgets.QMessageBox.warning(self, title, text)

    def _msg_info(self, title: str, text: str) -> None:
        QtWidgets.QMessageBox.information(self, title, text)

    def _confirm_yesno(self, title: str, text: str) -> bool:
        m = QtWidgets.QMessageBox(self)
        m.setWindowTitle(title)
        m.setText(text)
        m.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No)
        m.setDefaultButton(QtWidgets.QMessageBox.StandardButton.No)
        res = m.exec()
        return res == int(QtWidgets.QMessageBox.StandardButton.Yes)

    def _update_summary(self, dirs: int, size_b: int, errors: int, scanned: int) -> None:
        self.summary_label.setText(self.t("summary", dirs=dirs, size=format_bytes(size_b), errors=errors, scanned=scanned))

    def _populate_default_roots(self) -> None:
        self.roots_list.clear()

        # Home: checked by default
        home = os.path.expanduser("~")
        if home and os.path.exists(home):
            it = QtWidgets.QListWidgetItem(f"Home: {home}")
            it.setFlags(it.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(QtCore.Qt.CheckState.Checked)
            it.setData(QtCore.Qt.ItemDataRole.UserRole, home)
            self.roots_list.addItem(it)

        # Drives: unchecked by default (scanning full drives can take a long time)
        for d in list_windows_roots():
            it = QtWidgets.QListWidgetItem(d)
            it.setFlags(it.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(QtCore.Qt.CheckState.Unchecked)
            it.setData(QtCore.Qt.ItemDataRole.UserRole, d)
            self.roots_list.addItem(it)

    def _get_roots(self) -> List[str]:
        roots: List[str] = []
        for i in range(self.roots_list.count()):
            it = self.roots_list.item(i)
            if it.checkState() == QtCore.Qt.CheckState.Checked:
                p = it.data(QtCore.Qt.ItemDataRole.UserRole)
                if isinstance(p, str) and p and os.path.exists(p):
                    roots.append(p)

        # If nothing checked: fallback to home (if exists)
        if not roots:
            home = os.path.expanduser("~")
            if home and os.path.exists(home):
                roots = [home]
        return roots
        roots = []
        for i in range(self.roots_list.count()):
            p = self.roots_list.item(i).text().strip()
            if p and os.path.exists(p):
                roots.append(p)
        if not roots:
            home = os.path.expanduser("~")
            if home and os.path.exists(home):
                roots = [home]
        return roots

    def add_root(self) -> None:
        d = QtWidgets.QFileDialog.getExistingDirectory(self, self.t("add_root"), os.path.expanduser("~"))
        if not d:
            return
        d = os.path.abspath(d)
        it = QtWidgets.QListWidgetItem(d)
        it.setFlags(it.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
        it.setCheckState(QtCore.Qt.CheckState.Checked)
        it.setData(QtCore.Qt.ItemDataRole.UserRole, d)
        self.roots_list.addItem(it)

    def remove_selected_roots(self) -> None:
        for it in self.roots_list.selectedItems():
            row = self.roots_list.row(it)
            self.roots_list.takeItem(row)

    def clear_results(self) -> None:
        self.model.clear()
        self.log_box.clear()
        self._update_summary(0, 0, 0, 0)

    def start_scan(self) -> None:
        if self._busy():
            self._msg_warn(self.t("busy"), self.t("busy_msg"))
            return

        self.clear_results()
        roots = self._get_roots()

        exclude_common = self.cb_exclude.isChecked()
        follow_links = self.cb_follow.isChecked()
        calc_sizes = self.cb_calc_sizes.isChecked()

        self._scan_thread = QtCore.QThread()
        self._scan_worker = ScanWorker(
            roots=roots,
            exclude_common=exclude_common,
            follow_links=follow_links,
            calc_sizes=calc_sizes,
            batch_size=300,
        )
        self._scan_worker.moveToThread(self._scan_thread)

        self._scan_thread.started.connect(self._scan_worker.run)
        self._scan_worker.batch_found.connect(self.on_batch_found)
        self._scan_worker.progress.connect(self.on_scan_progress)
        self._scan_worker.finished.connect(self.on_scan_finished)
        self._scan_worker.log.connect(self._append_log)

        self._scan_thread.start()

        self.btn_scan.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress_bar.setRange(0, 0)
        self.progress_label.setText(self.t("scanning", path=""))

    def on_batch_found(self, items: list) -> None:
        self.model.add_items(items)
        QtWidgets.QApplication.processEvents()

    def on_scan_progress(self, info: dict) -> None:
        cur = info.get("current_path", "")
        found_dirs = int(info.get("found_dirs", 0))
        found_size = int(info.get("found_size_bytes", 0))
        errors = int(info.get("errors", 0))
        scanned = int(info.get("scanned_dirs", 0))
        if cur:
            self.progress_label.setText(self.t("scanning", path=cur))
        self._update_summary(found_dirs, found_size, errors, scanned)

    def on_scan_finished(self, stats: ScanStats) -> None:
        if self._scan_thread is not None:
            self._scan_thread.quit()
            self._scan_thread.wait(2000)
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

    def _selected_rows(self) -> List[int]:
        sel = self.view.selectionModel().selectedRows()
        return sorted({i.row() for i in sel})

    def delete_selected(self) -> None:
        if self._busy():
            self._msg_warn(self.t("busy"), self.t("busy_msg"))
            return
        rows = self._selected_rows()
        if not rows:
            self._msg_info("Info", self.t("nothing_selected"))
            return
        items = self.model.get_items_by_rows(rows)
        self._start_delete(items)

    def delete_all(self) -> None:
        if self._busy():
            self._msg_warn(self.t("busy"), self.t("busy_msg"))
            return
        if not self.model.items:
            self._msg_info("Info", self.t("nothing_found"))
            return
        self._start_delete(list(self.model.items))

    def _start_delete(self, items: List[FoundItem]) -> None:
        if not self._confirm_yesno("Confirm", self.t("confirm_delete", n=len(items))):
            return

        recalc = self.cb_recalc_del.isChecked()

        self._delete_thread = QtCore.QThread()
        self._delete_worker = DeleteWorker(items=items, recalc_size=recalc)
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
        self.summary_label.setText(
            f"Deleted: {deleted} • Failed: {failed} • Freed: {format_bytes(freed)} • Errors: {errors}"
        )

    def on_delete_finished(self, stats: DeleteStats) -> None:
        if self._delete_thread is not None:
            self._delete_thread.quit()
            self._delete_thread.wait(2000)
        self._delete_thread = None
        self._delete_worker = None

        remaining = [it for it in self.model.items if os.path.exists(it.path)]
        self.model.clear()
        self.model.add_items(remaining)

        self.btn_scan.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(1)
        self.progress_label.setText(self.t("ready"))

        self._append_log(self.t("delete_done", sec=stats.elapsed_s, deleted=stats.deleted,
                                failed=stats.failed, size=format_bytes(stats.freed_bytes)))
        if stats.cancelled:
            self._append_log("Cancelled.")

        self._update_summary(len(self.model.items), self.model.total_size(), 0, 0)

    def export_list(self) -> None:
        if not self.model.items:
            self._msg_info("Info", self.t("nothing_found"))
            return

        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Export", "pycache_list.txt", "Text files (*.txt);;All files (*.*)"
        )
        if not path:
            return
        try:
            total = 0
            with open(path, "w", encoding="utf-8") as f:
                for it in self.model.items:
                    total += it.size_bytes
                    f.write(f"{it.path}\t{it.size_bytes}\t{it.file_count}\n")
                f.write(f"\nTOTAL\t{total}\n")
            self._append_log(f"Exported: {path}")
        except Exception:
            self._append_log("Failed to export:\n" + traceback.format_exc())

    def open_selected_folder(self) -> None:
        rows = self._selected_rows()
        if not rows:
            self._msg_info("Info", self.t("nothing_selected"))
            return
        item = self.model.get_items_by_rows([rows[0]])[0]
        folder = os.path.dirname(item.path)
        try:
            if is_windows():
                os.startfile(folder)  # type: ignore[attr-defined]
            else:
                QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(folder))
        except Exception:
            self._append_log("Failed to open folder:\n" + traceback.format_exc())


def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

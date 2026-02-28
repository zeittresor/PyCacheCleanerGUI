# PyCache Cleaner GUI

A small Windows-friendly GUI tool to **find and delete Python `__pycache__` folders** so you can reclaim disk space.

`__pycache__` stores compiled bytecode (`.pyc`). Deleting it should be safe: Python will recreate it when needed. The trade-off is a slightly slower first import after cleaning.

<img width="1378" height="793" alt="PyCacheCleanerGUI" src="https://github.com/user-attachments/assets/5cdb803b-45a6-4927-b57c-fe51bf2d2d16" />

## Features

- GUI (PyQt6 preferred, PyQt5 fallback)
- Select scan roots (Home + drives)
- Shows:
  - number of found `__pycache__` folders
  - total reclaimable size (estimated)
  - error count (permissions / races)
- Delete:
  - selected rows
  - all found
- Export list to a `.txt` file

## Requirements

- Windows 10/11 (also works on Linux/macOS with minor differences)
- Python **3.10+** recommended
- Either:
  - `PyQt6` (recommended) or
  - `PyQt5` (fallback)

Install:

```bash
pip install PyQt6
# or:
pip install PyQt5
```

## Run

```bash
python pycache_cleaner_gui.py
```

## Notes / Safety

- The delete action **only removes folders that are literally named `__pycache__`**.
- If you scan full drives, it can take a long time. Default selection is your **Home** folder to keep scans practical.
- Permission errors are expected when scanning system areas; they are counted and logged.

## Optional: build an EXE

If you want a standalone exe:

```bash
pip install pyinstaller
pyinstaller --noconsole --onefile pycache_cleaner_gui.py
```

The exe will appear in `dist/`.

## License

MIT (do whatever you want, no warranty).

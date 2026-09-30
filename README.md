# Secure File Integrity Checker

A beginner-friendly Cyber Security mini project that demonstrates file integrity verification using SHA-256 cryptographic hashing.

## Problem Statement

Files can be modified accidentally or maliciously without an obvious visual sign. This application creates a trusted SHA-256 baseline and compares future file versions against it.

## Objectives

- Generate SHA-256 hashes for selected files.
- Store file metadata and trusted hashes locally.
- Detect even small file modifications.
- Present verification results and history in a clear GUI.

## Technologies Used

- Python 3.10 or newer
- Tkinter desktop GUI
- JSON local data storage
- Standard library only

## Python Libraries Used

- `hashlib` for SHA-256 hashing
- `tkinter` and `tkinter.ttk` for the interface
- `json` for local persistence
- `pathlib` for safe path handling
- `datetime` for timestamps

## CNS Concepts Used

Cryptographic hashing, message digests, data integrity, tamper detection, baseline comparison, and secure file verification.

## Key Features

- Browse any file and view its name, path, size, and type.
- Calculate and copy a complete SHA-256 hash.
- Register multiple file baselines in `data/integrity_records.json`.
- Verify registered files and show original/current hashes when changed.
- Dashboard counters for registered, verified, and compromised files.
- Persistent registration and verification history.
- Input validation for missing, deleted, unreadable, and unregistered files.
- File contents are never stored; only metadata and hashes are saved.

## System Requirements

- Windows, macOS, or Linux
- Python 3.10+
- Tkinter installed. It is included with most Python installations. On some Linux distributions install the `python3-tk` package.

## Installation Steps

1. Download or clone this project.
2. Open a terminal in the `Secure-File-Integrity-Checker` folder.
3. Optional: create and activate a virtual environment.
4. No third-party packages are required. `requirements.txt` is included for project documentation.

## How to Run

```bash
python main.py
```

## Project Workflow

1. Open **Hash Generator** and browse to a file.
2. Generate its SHA-256 hash.
3. Save the integrity record.
4. Later, open **Verify Integrity**, select the registered path, and run verification.
5. A matching hash displays `File Integrity Verified - File Not Modified`.
6. A changed hash displays `File Integrity Compromised - File Modified`, including both hashes.
7. Review all baselines and verification events in **History** and summary counts in **Dashboard**.

## Screenshots

Place screenshots of the Dashboard, Hash Generator, Verify Integrity, and History tabs in the `screenshots/` folder for a final report or presentation.

## Future Scope

- Password-protected records.
- Optional scheduled integrity checks.
- Email or desktop alerts for compromised files.
- Exportable PDF or CSV reports.
- Directory-level recursive monitoring.

## Conclusion

Secure File Integrity Checker provides a practical demonstration of how SHA-256 hashing can identify file tampering. It combines a simple workflow with persistent records and a professional Tkinter interface suitable for a college CNS demonstration.

## GitHub Repository

Add the repository URL here after publishing the project to GitHub.

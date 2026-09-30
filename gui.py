"""Tkinter user interface for the Secure File Integrity Checker."""

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from database import IntegrityDatabase
from hash_utils import calculate_sha256, format_file_size, get_file_metadata


APP_TITLE = "Secure File Integrity Checker"


class SecureFileIntegrityApp(tk.Tk):
    """Main application window and tab controller."""

    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1100x720")
        self.minsize(900, 620)
        self.configure(bg="#eef3f8")
        self.database = IntegrityDatabase()
        self.selected_hash_path: Path | None = None
        self.selected_verify_path: Path | None = None
        self._configure_styles()
        self._build_interface()
        self.refresh_all()

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#eef3f8")
        style.configure("Content.TFrame", background="#ffffff")
        style.configure("Header.TFrame", background="#16324f")
        style.configure("TLabel", background="#eef3f8", foreground="#263746", font=("Segoe UI", 10))
        style.configure("Header.TLabel", background="#16324f", foreground="#ffffff")
        style.configure("Title.TLabel", background="#16324f", foreground="#ffffff", font=("Segoe UI", 22, "bold"))
        style.configure("Subtitle.TLabel", background="#16324f", foreground="#c8d8e8", font=("Segoe UI", 10))
        style.configure("Section.TLabel", background="#ffffff", foreground="#16324f", font=("Segoe UI", 15, "bold"))
        style.configure("CardValue.TLabel", background="#ffffff", foreground="#16324f", font=("Segoe UI", 24, "bold"))
        style.configure("CardCaption.TLabel", background="#ffffff", foreground="#607486", font=("Segoe UI", 10))
        style.configure("Hash.TLabel", background="#f3f7fb", foreground="#173d5d", font=("Consolas", 10))
        style.configure("Status.TLabel", background="#eef3f8", foreground="#536979", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10), padding=(12, 7))
        style.configure("Accent.TButton", background="#0b7285", foreground="#ffffff", font=("Segoe UI", 10, "bold"))
        style.map("Accent.TButton", background=[("active", "#095c6b")])
        style.configure("Treeview", rowheight=28, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("TNotebook", background="#eef3f8", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(18, 9), font=("Segoe UI", 10, "bold"))
        style.configure("TCombobox", padding=5)

    def _build_interface(self) -> None:
        header = ttk.Frame(self, style="Header.TFrame", padding=(28, 20))
        header.pack(fill="x")
        ttk.Label(header, text="SECURE FILE INTEGRITY CHECKER", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="SHA-256 powered protection for your important files", style="Subtitle.TLabel").pack(anchor="w", pady=(3, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=18, pady=18)
        self.dashboard_tab = ttk.Frame(self.notebook, padding=20)
        self.hash_tab = ttk.Frame(self.notebook, padding=20)
        self.verify_tab = ttk.Frame(self.notebook, padding=20)
        self.history_tab = ttk.Frame(self.notebook, padding=20)
        self.about_tab = ttk.Frame(self.notebook, padding=20)
        for tab, title in ((self.dashboard_tab, "Dashboard"), (self.hash_tab, "Hash Generator"), (self.verify_tab, "Verify Integrity"), (self.history_tab, "History"), (self.about_tab, "About")):
            self.notebook.add(tab, text=title)
        self._build_dashboard()
        self._build_hash_generator()
        self._build_verifier()
        self._build_history()
        self._build_about()
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, style="Status.TLabel", padding=(20, 0, 20, 10)).pack(fill="x")

    def _build_dashboard(self) -> None:
        ttk.Label(self.dashboard_tab, text="Security Dashboard", style="Section.TLabel").pack(anchor="w")
        ttk.Label(self.dashboard_tab, text="A quick view of your registered files and recent security checks.").pack(anchor="w", pady=(4, 18))
        cards = ttk.Frame(self.dashboard_tab)
        cards.pack(fill="x")
        self.dashboard_values: dict[str, tk.StringVar] = {}
        card_data = (("registered", "TOTAL FILES REGISTERED"), ("verified", "FILES VERIFIED"), ("compromised", "MODIFIED / COMPROMISED"), ("last_verification", "LAST VERIFICATION"))
        for key, caption in card_data:
            card = ttk.Frame(cards, style="Content.TFrame", padding=18)
            card.pack(side="left", fill="both", expand=True, padx=(0, 12))
            value = tk.StringVar(value="0")
            self.dashboard_values[key] = value
            ttk.Label(card, textvariable=value, style="CardValue.TLabel").pack(anchor="w")
            ttk.Label(card, text=caption, style="CardCaption.TLabel").pack(anchor="w", pady=(8, 0))
        info = ttk.Frame(self.dashboard_tab, style="Content.TFrame", padding=20)
        info.pack(fill="both", expand=True, pady=(24, 0))
        ttk.Label(info, text="Getting started", style="Section.TLabel").pack(anchor="w")
        ttk.Label(info, text="1. Use Hash Generator to select a file and create its SHA-256 fingerprint.\n2. Save the fingerprint as an integrity record.\n3. Use Verify Integrity later to detect any change, even one changed character.\n\nYour files are never copied or stored. Only metadata, hashes, and verification results are saved locally.", justify="left").pack(anchor="w", pady=(12, 0))

    def _build_hash_generator(self) -> None:
        ttk.Label(self.hash_tab, text="Generate SHA-256 Hash", style="Section.TLabel").pack(anchor="w")
        ttk.Label(self.hash_tab, text="Select a file, calculate its cryptographic fingerprint, then save it as a baseline record.").pack(anchor="w", pady=(4, 18))
        self.hash_file_var = tk.StringVar(value="No file selected")
        ttk.Label(self.hash_tab, textvariable=self.hash_file_var, background="#f3f7fb", padding=12).pack(fill="x")
        controls = ttk.Frame(self.hash_tab)
        controls.pack(fill="x", pady=12)
        ttk.Button(controls, text="Browse File", command=self.choose_hash_file).pack(side="left")
        ttk.Button(controls, text="Generate Hash", style="Accent.TButton", command=self.generate_hash).pack(side="left", padx=8)
        ttk.Button(controls, text="Copy Hash", command=self.copy_hash).pack(side="left")
        self.hash_value = tk.StringVar(value="Hash will appear here")
        ttk.Label(self.hash_tab, textvariable=self.hash_value, style="Hash.TLabel", padding=14, wraplength=1000).pack(fill="x", pady=(4, 14))
        self.hash_metadata = tk.StringVar(value="File details will appear here after selection.")
        ttk.Label(self.hash_tab, textvariable=self.hash_metadata, justify="left").pack(anchor="w")
        ttk.Button(self.hash_tab, text="Save Integrity Record", style="Accent.TButton", command=self.save_integrity_record).pack(anchor="w", pady=20)

    def _build_verifier(self) -> None:
        ttk.Label(self.verify_tab, text="Verify File Integrity", style="Section.TLabel").pack(anchor="w")
        ttk.Label(self.verify_tab, text="Choose a registered file or browse to its current location, then compare its current hash with the saved baseline.").pack(anchor="w", pady=(4, 18))
        ttk.Label(self.verify_tab, text="Registered files").pack(anchor="w")
        self.registered_paths: list[str] = []
        self.verify_choice = tk.StringVar()
        self.verify_combo = ttk.Combobox(self.verify_tab, textvariable=self.verify_choice, state="readonly")
        self.verify_combo.pack(fill="x", pady=(4, 10))
        controls = ttk.Frame(self.verify_tab)
        controls.pack(fill="x")
        ttk.Button(controls, text="Browse File", command=self.choose_verify_file).pack(side="left")
        ttk.Button(controls, text="Verify Selected File", style="Accent.TButton", command=self.verify_file).pack(side="left", padx=8)
        self.verify_file_var = tk.StringVar(value="No file selected")
        ttk.Label(self.verify_tab, textvariable=self.verify_file_var, padding=12, background="#f3f7fb").pack(fill="x", pady=14)
        self.verify_result = tk.StringVar(value="Verification result will appear here.")
        ttk.Label(self.verify_tab, textvariable=self.verify_result, font=("Segoe UI", 14, "bold"), wraplength=1000).pack(anchor="w", pady=(10, 16))
        self.verify_details = tk.StringVar()
        ttk.Label(self.verify_tab, textvariable=self.verify_details, style="Hash.TLabel", padding=14, justify="left", wraplength=1000).pack(fill="x")

    def _build_history(self) -> None:
        ttk.Label(self.history_tab, text="Integrity History", style="Section.TLabel").pack(anchor="w")
        toolbar = ttk.Frame(self.history_tab)
        toolbar.pack(fill="x", pady=(8, 10))
        ttk.Button(toolbar, text="Refresh", command=self.refresh_all).pack(side="left")
        ttk.Button(toolbar, text="Clear Verification History", command=self.clear_history).pack(side="left", padx=8)
        ttk.Label(self.history_tab, text="Registered file baselines").pack(anchor="w")
        record_frame = ttk.Frame(self.history_tab)
        record_frame.pack(fill="both", expand=True, pady=(4, 12))
        self.records_tree = self._make_tree(record_frame, ("name", "path", "hash", "registered"), ("File", "Path", "SHA-256", "Registered"), (170, 270, 440, 160))
        ttk.Label(self.history_tab, text="Verification events").pack(anchor="w")
        verification_frame = ttk.Frame(self.history_tab)
        verification_frame.pack(fill="both", expand=True, pady=(4, 0))
        self.verifications_tree = self._make_tree(verification_frame, ("name", "status", "verified_at", "original", "current"), ("File", "Status", "Date / Time", "Original Hash", "Current Hash"), (150, 120, 170, 300, 300))

    def _make_tree(self, parent: ttk.Frame, columns: tuple[str, ...], headings: tuple[str, ...], widths: tuple[int, ...]) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=columns, show="headings", height=5)
        for column, heading, width in zip(columns, headings, widths):
            tree.heading(column, text=heading)
            tree.column(column, width=width, anchor="w")
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        return tree

    def _build_about(self) -> None:
        ttk.Label(self.about_tab, text="About This Project", style="Section.TLabel").pack(anchor="w")
        about_text = (
            "PROJECT NAME\nSecure File Integrity Checker\n\n"
            "PROBLEM STATEMENT\nFiles can be changed accidentally or maliciously without an obvious visual sign. A reliable integrity check is needed to detect those changes.\n\n"
            "OBJECTIVE\nGenerate a SHA-256 fingerprint for a file, save it as a trusted baseline, and compare it with future versions.\n\n"
            "SHA-256 EXPLANATION\nSHA-256 is a cryptographic hash function. It converts file data into a fixed 64-character hexadecimal digest. A tiny input change produces a different digest, making it useful for integrity verification.\n\n"
            "TECHNOLOGIES\nPython, Tkinter GUI, JSON local storage, hashlib SHA-256\n\n"
            "CNS CONCEPT DEMONSTRATED\nCryptographic hashing, message digests, data integrity, tamper detection, and secure verification workflows."
        )
        ttk.Label(self.about_tab, text=about_text, justify="left", wraplength=950).pack(anchor="w", pady=(14, 0))

    def choose_hash_file(self) -> None:
        path = filedialog.askopenfilename(title="Select a file to hash")
        if path:
            self.selected_hash_path = Path(path)
            self.hash_file_var.set(str(self.selected_hash_path))
            try:
                metadata = get_file_metadata(path)
                self.hash_metadata.set(f"Name: {metadata['name']}\nSize: {format_file_size(int(metadata['size']))}\nType: {metadata['type']}\nPath: {metadata['path']}")
                self.hash_value.set("Click Generate Hash to calculate the digest")
                self.status_var.set("File selected")
            except (OSError, ValueError) as error:
                self._show_error("File Selection Error", str(error))

    def generate_hash(self) -> None:
        if not self.selected_hash_path:
            self._show_error("No File Selected", "Please browse and select a file first.")
            return
        try:
            self.hash_value.set(calculate_sha256(self.selected_hash_path))
            self.status_var.set("SHA-256 hash generated successfully")
        except (OSError, ValueError) as error:
            self._show_error("Hash Error", str(error))

    def copy_hash(self) -> None:
        value = self.hash_value.get()
        if len(value) != 64:
            self._show_error("No Hash Available", "Generate a SHA-256 hash before copying it.")
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.status_var.set("Hash copied to clipboard")

    def save_integrity_record(self) -> None:
        if not self.selected_hash_path or len(self.hash_value.get()) != 64:
            self._show_error("Incomplete Record", "Select a file and generate its SHA-256 hash first.")
            return
        try:
            self.database.register_file(get_file_metadata(self.selected_hash_path), self.hash_value.get())
            self.refresh_all()
            self.status_var.set("Integrity record saved")
            messagebox.showinfo("Record Saved", "The file's metadata and SHA-256 hash were saved successfully.")
        except (OSError, ValueError) as error:
            self._show_error("Save Error", str(error))

    def choose_verify_file(self) -> None:
        path = filedialog.askopenfilename(title="Select a file to verify")
        if path:
            self.selected_verify_path = Path(path)
            self.verify_choice.set("")
            self.verify_file_var.set(str(self.selected_verify_path))
            self.status_var.set("Verification file selected")

    def verify_file(self) -> None:
        path = self.selected_verify_path
        if not path and self.verify_choice.get():
            path = Path(self.verify_choice.get())
        if not path:
            self._show_error("No File Selected", "Choose a registered file or browse to a file first.")
            return
        record = self.database.get_record(path)
        if not record:
            self._show_error("File Not Registered", "This file has no saved baseline. Register it using Hash Generator first.")
            return
        try:
            current_hash = calculate_sha256(path)
            is_verified = current_hash == record["hash"]
            status = "verified" if is_verified else "compromised"
            self.database.add_verification(str(path), record["hash"], current_hash, status)
            if is_verified:
                self.verify_result.set("✓ File Integrity Verified - File Not Modified")
            else:
                self.verify_result.set("⚠ File Integrity Compromised - File Modified")
            self.verify_details.set(f"Original SHA-256:\n{record['hash']}\n\nCurrent SHA-256:\n{current_hash}")
            self.refresh_all()
            self.status_var.set("Verification completed")
        except (OSError, ValueError) as error:
            self._show_error("Verification Error", f"The file may have been deleted or cannot be read.\n\n{error}")

    def clear_history(self) -> None:
        if messagebox.askyesno("Clear History", "Delete all verification events? Registered file baselines will remain."):
            self.database.clear_history()
            self.refresh_all()
            self.verify_result.set("Verification result will appear here.")
            self.verify_details.set("")
            self.status_var.set("Verification history cleared")

    def refresh_all(self) -> None:
        stats = self.database.dashboard_stats()
        for key, value in stats.items():
            if key in self.dashboard_values:
                self.dashboard_values[key].set(str(value))
        records = self.database.get_records()
        self.registered_paths = [record["path"] for record in records]
        self.verify_combo["values"] = self.registered_paths
        self._fill_tree(self.records_tree, records, (("name",), ("path",), ("hash",), ("registered_at",)))
        self._fill_tree(self.verifications_tree, self.database.get_verifications(), (("name",), ("status",), ("verified_at",), ("original_hash",), ("current_hash",)))

    @staticmethod
    def _fill_tree(tree: ttk.Treeview, rows: list[dict[str, str]], fields: tuple[tuple[str, ...], ...]) -> None:
        for item in tree.get_children():
            tree.delete(item)
        for row in rows:
            tree.insert("", "end", values=tuple(row.get(field[0], "") for field in fields))

    @staticmethod
    def _show_error(title: str, message: str) -> None:
        messagebox.showerror(title, message)


if __name__ == "__main__":
    SecureFileIntegrityApp().mainloop()

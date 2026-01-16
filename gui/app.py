"""
Main application window for the Security Scanner.
"""

import customtkinter as ctk
import validators
import threading
from tkinter import messagebox
from gui.components import URLInputFrame, ScanControlFrame, ResultsFrame, StatusBar
from scanner.core import Scanner


class SecurityScannerApp:
    """Main application class."""

    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.window = ctk.CTk()
        self.window.title("Security Scanner")
        self.window.geometry("900x700")
        self.window.minsize(800, 600)

        self.window.grid_columnconfigure(0, weight=1)
        self.window.grid_rowconfigure(2, weight=1)

        self.scanning = False

        self._setup_ui()
        self._bind_events()

    def _setup_ui(self):
        """Initialize the user interface components."""
        self.url_frame = URLInputFrame(self.window)
        self.url_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)

        self.control_frame = ScanControlFrame(self.window)
        self.control_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)

        self.results_frame = ResultsFrame(self.window)
        self.results_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=10)

        self.status_bar = StatusBar(self.window)
        self.status_bar.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 10))

    def _bind_events(self):
        """Connect UI events to handler methods."""
        self.control_frame.scan_button.configure(command=self.start_scan)
        self.control_frame.stop_button.configure(command=self.stop_scan)
        self.control_frame.clear_button.configure(command=self.clear_results)
        self.url_frame.url_entry.bind("<Return>", lambda e: self.start_scan())

    def start_scan(self):
        """Handle the start scan button click."""
        url = self.url_frame.get_url()

        # Validate URL
        if not url:
            self.show_error("Please enter a URL to scan.")
            return

        if not validators.url(url):
            self.show_error("Please enter a valid URL (e.g., https://example.com)")
            return

        # Check authorization
        if not self.show_authorization_dialog():
            return

        # Update UI for scanning state
        self.scanning = True
        self.control_frame.set_scanning_state(True)
        self.status_bar.set_status(f"Scanning {url}...")
        self.status_bar.set_progress(0)
        self.results_frame.clear()
        self.status_bar.set_finding_count(0)

        # Start scan in background thread
        scan_thread = threading.Thread(target=self._run_scan_thread, args=(url,), daemon=True)
        scan_thread.start()

    def _run_scan_thread(self, url: str):
        """
        Run the scan in a background thread.

        IMPORTANT: This runs in a separate thread, so we can't update the GUI directly.
        We must use window.after() to schedule GUI updates on the main thread.

        Args:
            url: The URL to scan
        """
        # Create scanner and run scan
        scanner = Scanner(url)
        success, message, findings = scanner.run_scan()

        # Check if scan was stopped
        if not self.scanning:
            return

        # Schedule GUI updates on main thread
        if success:
            # Add each finding to the GUI
            for finding in findings:
                # Convert Finding object to dict for GUI
                finding_dict = finding.to_dict()
                self.window.after(0, self.add_result, finding_dict)

            # Mark scan complete
            self.window.after(0, self.on_scan_complete)
        else:
            # Show error
            self.window.after(0, self.show_error, message)
            self.window.after(0, self.on_scan_complete)

    def stop_scan(self):
        """Handle the stop scan button click."""
        self.scanning = False
        self.control_frame.set_scanning_state(False)
        self.status_bar.set_status("Scan stopped")

    def clear_results(self):
        """Clear all scan results from the display."""
        self.results_frame.clear()
        self.status_bar.set_finding_count(0)
        self.status_bar.set_progress(0)
        self.status_bar.set_status("Ready")

    def add_result(self, finding: dict):
        """Add a scan result to the results display."""
        self.results_frame.add_finding(finding)
        self.status_bar.set_finding_count(self.results_frame.get_finding_count())

    def on_scan_complete(self):
        """Handle scan completion."""
        self.scanning = False
        self.control_frame.set_scanning_state(False)
        count = self.results_frame.get_finding_count()
        self.status_bar.set_status(f"Scan complete - {count} finding(s)")
        self.status_bar.set_progress(1.0)

    def show_error(self, message: str):
        """Display an error message to the user."""
        messagebox.showerror("Error", message)

    def show_authorization_dialog(self) -> bool:
        """Show dialog confirming user has authorization to scan."""
        warning_text = (
            "WARNING: Only scan targets you own or have explicit "
            "written permission to test.\n\n"
            "Unauthorized scanning is illegal and unethical.\n\n"
            "Do you have authorization to scan this target?"
        )
        return messagebox.askyesno("Authorization Required", warning_text)

    def run(self):
        """Start the application main loop."""
        self.window.mainloop()

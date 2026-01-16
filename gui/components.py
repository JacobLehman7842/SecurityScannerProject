"""
Reusable UI components for the Security Scanner.
"""

import customtkinter as ctk


class URLInputFrame(ctk.CTkFrame):
    """Frame containing the URL input field and related controls."""

    def __init__(self, parent):
        super().__init__(parent)
        self.grid_columnconfigure(1, weight=1)
        
        
        self._create_widgets()

    def _create_widgets(self):
        """Create the URL input widgets."""
        self.url_label = ctk.CTkLabel(self, text="Target URL:")
        self.url_label.grid(row=0, column=0, padx=10, pady=10)
        
        self.url_entry = ctk.CTkEntry(self, placeholder_text="https://example.com", width=400)
        self.url_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        
        self.validate_btn = ctk.CTkButton(self, text="Validate", width=80)
        self.validate_btn.grid(row=0, column=2, padx=10, pady=10)

    def get_url(self) -> str:
        """Return the current URL from the entry field."""
        return self.url_entry.get().strip()

    def set_url(self, url: str):
        """Set the URL in the entry field."""
        self.url_entry.delete(0, "end")
        self.url_entry.insert(0, url)

    def set_enabled(self, enabled: bool):
        """Enable or disable the URL input."""
        state = "normal" if enabled else "disabled"
        self.url_entry.configure(state=state)


class ScanControlFrame(ctk.CTkFrame):
    """Frame containing scan control buttons."""

    def __init__(self, parent):
        super().__init__(parent)
        self._create_widgets()

    def _create_widgets(self):
        """Create the control buttons."""
        # Start button (green)
        self.scan_button = ctk.CTkButton(self, text="Start Scan", fg_color="green", hover_color="darkgreen")
        self.scan_button.pack(side="left", padx=10, pady=10)

        # Stop button (red, starts disabled)
        self.stop_button = ctk.CTkButton(self, text="Stop", fg_color="red", hover_color="darkred", state="disabled")
        self.stop_button.pack(side="left", padx=10, pady=10)

        # Clear button
        self.clear_button = ctk.CTkButton(self, text="Clear Results")
        self.clear_button.pack(side="left", padx=10, pady=10)

        # Scan type dropdown
        self.scan_types = ctk.CTkOptionMenu(self, values=["Full Scan", "Headers Only", "Files Only"])
        self.scan_types.pack(side="left", padx=10, pady=10)

    def set_scanning_state(self, is_scanning: bool):
        """Update button states based on whether a scan is in progress."""
        if is_scanning:
            self.scan_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
        else:
            self.scan_button.configure(state="normal")
            self.stop_button.configure(state="disabled")


class ResultsFrame(ctk.CTkScrollableFrame):
    """Scrollable frame for displaying scan results."""

    def __init__(self, parent):
        super().__init__(parent)
        self.result_widgets = []
        self.grid_columnconfigure(0, weight=1)

    def add_finding(self, finding: dict):
        """Add a finding card to the results display."""
        card = FindingCard(self, finding)
        card.grid(row=len(self.result_widgets), column=0, sticky="ew", pady=5, padx=5)
        self.result_widgets.append(card)

    def clear(self):
        """Remove all findings from the display."""
        for widget in self.result_widgets:
            widget.destroy()
        self.result_widgets = []

    def get_finding_count(self) -> int:
        """Return the number of findings displayed."""
        return len(self.result_widgets)


class FindingCard(ctk.CTkFrame):
    """A card displaying a single vulnerability finding."""

    # Color mapping for severity levels
    SEVERITY_COLORS = {
        "critical": "#dc2626",  # Red
        "high": "#ea580c",      # Orange
        "medium": "#ca8a04",    # Yellow/Gold
        "low": "#2563eb",       # Blue
        "info": "#6b7280",      # Gray
    }

    def __init__(self, parent, finding: dict):
        super().__init__(parent)
        self.finding = finding
        self.configure(corner_radius=10, border_width=2)
        self.configure(border_color=self.SEVERITY_COLORS.get(finding["severity"], "#6b7280"))
        self._create_widgets(finding)

    def _create_widgets(self, finding: dict):
        """Create the card content widgets."""
        self.grid_columnconfigure(0, weight=1)

        # Header with title and severity badge
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))

        title_label = ctk.CTkLabel(header_frame, text=finding["title"], font=("", 14, "bold"))
        title_label.pack(side="left")

        severity_color = self.SEVERITY_COLORS.get(finding["severity"], "#6b7280")
        severity_label = ctk.CTkLabel(
            header_frame,
            text=finding["severity"].upper(),
            fg_color=severity_color,
            corner_radius=5,
            text_color="white"
        )
        severity_label.pack(side="right", padx=5)

        # Description
        desc_label = ctk.CTkLabel(self, text=finding["description"], wraplength=500, justify="left")
        desc_label.grid(row=1, column=0, sticky="w", padx=10, pady=5)

        # Recommendation
        rec_label = ctk.CTkLabel(
            self,
            text=f"Recommendation: {finding['recommendation']}",
            wraplength=500,
            justify="left",
            text_color="#888888"
        )
        rec_label.grid(row=2, column=0, sticky="w", padx=10, pady=(5, 10))


class StatusBar(ctk.CTkFrame):
    """Status bar showing current scanner state and progress."""

    def __init__(self, parent):
        super().__init__(parent, height=40)
        self.grid_propagate(False)
        self._create_widgets()

    def _create_widgets(self):
        """Create status bar widgets."""
        # Status label on the left
        self.status_label = ctk.CTkLabel(self, text="Ready")
        self.status_label.pack(side="left", padx=10, pady=5)

        # Finding count on the right
        self.count_label = ctk.CTkLabel(self, text="Findings: 0")
        self.count_label.pack(side="right", padx=10, pady=5)

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self, width=200)
        self.progress_bar.pack(side="right", padx=10, pady=5)
        self.progress_bar.set(0)

    def set_status(self, message: str):
        """Update the status message."""
        self.status_label.configure(text=message)

    def set_progress(self, value: float):
        """Update the progress bar (0.0 to 1.0)."""
        self.progress_bar.set(value)

    def set_finding_count(self, count: int):
        """Update the finding count display."""
        self.count_label.configure(text=f"Findings: {count}")

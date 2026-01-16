"""
Test file for GUI components.
Run this to test individual components as you build them.
"""

import customtkinter as ctk
from gui.components import URLInputFrame, ScanControlFrame, ResultsFrame, StatusBar

# Set appearance before creating any widgets
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Create main window
root = ctk.CTk()
root.title("Component Test")
root.geometry("800x600")
root.grid_columnconfigure(0, weight=1)
root.grid_rowconfigure(2, weight=1)  # Results frame expands

# Test URLInputFrame
url_frame = URLInputFrame(root)
url_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)

# Test ScanControlFrame
control_frame = ScanControlFrame(root)
control_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)

# Test ResultsFrame
results_frame = ResultsFrame(root)
results_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=10)

# Test StatusBar
status_bar = StatusBar(root)
status_bar.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 10))

# Sample findings to test with
sample_findings = [
    {
        "title": "Missing X-Frame-Options Header",
        "severity": "medium",
        "description": "The X-Frame-Options header is not set, which could allow clickjacking attacks.",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to response headers."
    },
    {
        "title": "SQL Injection Detected",
        "severity": "critical",
        "description": "SQL error message found in response, indicating possible SQL injection vulnerability.",
        "recommendation": "Use parameterized queries and input validation."
    },
    {
        "title": "Missing HTTPS Redirect",
        "severity": "high",
        "description": "The site does not redirect HTTP to HTTPS.",
        "recommendation": "Implement automatic HTTPS redirect for all traffic."
    },
    {
        "title": "Server Version Disclosed",
        "severity": "low",
        "description": "The server is disclosing its version in response headers.",
        "recommendation": "Configure server to hide version information."
    },
    {
        "title": "Robots.txt Found",
        "severity": "info",
        "description": "robots.txt file is publicly accessible.",
        "recommendation": "Review robots.txt to ensure no sensitive paths are disclosed."
    },
]

finding_index = 0

def add_sample_finding():
    """Add the next sample finding to test the results display."""
    global finding_index
    if finding_index < len(sample_findings):
        results_frame.add_finding(sample_findings[finding_index])
        finding_index += 1
        status_bar.set_finding_count(results_frame.get_finding_count())
        status_bar.set_progress(finding_index / len(sample_findings))
        print(f"Added finding {finding_index}/{len(sample_findings)}")
    else:
        print("No more sample findings")

def clear_findings():
    """Clear all findings from results."""
    global finding_index
    results_frame.clear()
    finding_index = 0
    status_bar.set_finding_count(0)
    status_bar.set_progress(0)
    status_bar.set_status("Ready")
    print("Cleared all findings")

def simulate_scan():
    """Simulate scanning state."""
    control_frame.set_scanning_state(True)
    status_bar.set_status("Scanning...")
    print("Scanning started")

def simulate_complete():
    """Simulate scan completion."""
    control_frame.set_scanning_state(False)
    status_bar.set_status(f"Scan complete - {results_frame.get_finding_count()} findings")
    print("Scan complete")

# Wire up button commands
control_frame.scan_button.configure(command=simulate_scan)
control_frame.stop_button.configure(command=simulate_complete)
control_frame.clear_button.configure(command=clear_findings)

# Extra test button to add findings
add_btn = ctk.CTkButton(root, text="Add Sample Finding", command=add_sample_finding)
add_btn.grid(row=4, column=0, pady=10)

# Start the app
root.mainloop()

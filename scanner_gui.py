import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from pathlib import Path
from threatsweeper import MalwareScanner

class MalwareScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ThreatSweeper")
        self.root.geometry("700x500")
        self.root.configure(bg="#1e1e1e")
        
        try:
            self.scanner = MalwareScanner()
        except Exception as e:
            messagebox.showerror("Error", f"Initialization failed:\n{str(e)}")
            self.root.destroy()
            return

        # GUI Elements
        self.header = tk.Label(
            root,
            text="⚔️ THREATSWEEPER ⚔️",
            font=("Courier", 18, "bold"),
            bg="#1e1e1e",
            fg="#00ff00"
        )
        self.header.pack(pady=10)

        self.scan_button = tk.Button(
            root,
            text="🔍 SCAN FILE",
            command=self.scan_file,
            height=2,
            width=20,
            bg="#333333",
            fg="#00ff00",
            font=("Courier", 10, "bold"),
            relief=tk.RAISED,
            bd=3
        )
        self.scan_button.pack(pady=15)

        self.report_display = scrolledtext.ScrolledText(
            root,
            wrap=tk.WORD,
            width=80,
            height=20,
            font=("Courier", 10),
            bg="#1e1e1e",
            fg="#00ff00",
            insertbackground="#00ff00"
        )
        self.report_display.pack(pady=10, padx=10)
        self.report_display.insert(tk.END, "Ready to scan...\n\nSelect a file to begin analysis.")
        self.report_display.configure(state='disabled')

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("🟢 READY")
        self.status_bar = tk.Label(
            root,
            textvariable=self.status_var,
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W,
            bg="#333333",
            fg="#00ff00",
            font=("Courier", 8)
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def scan_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
            
        self.status_var.set("🟠 SCANNING...")
        self.root.update()
        
        try:
            is_malicious, report = self.scanner.scan_file(file_path)
            self.report_display.configure(state='normal')
            self.report_display.delete(1.0, tk.END)
            self.report_display.insert(tk.END, report)
            
            # Color coding
            if is_malicious:
                self.report_display.tag_config("alert", foreground="#ff0000")
                self.report_display.tag_add("alert", "1.0", tk.END)
            else:
                self.report_display.tag_config("safe", foreground="#00ff00")
                self.report_display.tag_add("safe", "1.0", tk.END)
                
            self.report_display.configure(state='disabled')
            
        except Exception as e:
            self.report_display.configure(state='normal')
            self.report_display.delete(1.0, tk.END)
            self.report_display.insert(tk.END, f"❌ ERROR:\n{str(e)}")
            self.report_display.configure(state='disabled')
        finally:
            self.status_var.set(f"🟢 READY | Last scan: {Path(file_path).name}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MalwareScannerApp(root)
    root.mainloop()

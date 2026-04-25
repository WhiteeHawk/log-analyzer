import tkinter as tk
from tkinter import filedialog, scrolledtext
from datetime import datetime
from analyzer import analyze_file
import threading
import matplotlib.pyplot as plt

# -------- Colors --------
BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
ACCENT = "#22c55e"
TEXT = "#e2e8f0"

# -------- Window --------
root = tk.Tk()
root.title("Cyber Log Analyzer")
root.geometry("900x550")
root.config(bg=BG_COLOR)

# -------- Store last result --------
last_result = None

# -------- Title --------
tk.Label(root, text="🔐 Log Analyzer",
         font=("Arial", 18, "bold"),
         bg=BG_COLOR, fg=ACCENT).pack(pady=10)

# -------- Frame --------
frame = tk.Frame(root, bg=CARD_COLOR)
frame.pack(padx=20, pady=10, fill="both", expand=True)

# -------- Output --------
log_area = scrolledtext.ScrolledText(
    frame,
    wrap=tk.WORD,
    bg="#020617",
    fg=TEXT,
    font=("Consolas", 10)
)
log_area.pack(padx=10, pady=10, fill="both", expand=True)

# -------- Status --------
status = tk.Label(root,
                  text="Status: Waiting...",
                  bg=BG_COLOR, fg=TEXT)
status.pack(pady=5)

# -------- Analyzer --------
def analyze_logs(file_path):
    try:
        result = analyze_file(file_path)

        global last_result
        last_result = result

        def update_ui():
            log_area.delete(1.0, tk.END)

            # 🔥 Dashboard Title
            log_area.insert(tk.END, "=== 🔐 Cyber Security Dashboard ===\n\n")

            # -------- Overview --------
            log_area.insert(tk.END, "📊 Overview:\n")
            log_area.insert(tk.END, f"Total Logs: {result['total']}\n")
            log_area.insert(tk.END, f"Failed Logins: {result['failed']}\n")
            log_area.insert(tk.END, f"Success Logins: {result['success']}\n\n")

            # -------- Top IPs --------
            log_area.insert(tk.END, "🔥 Top IPs:\n")
            for ip, count in result["top_ips"]:
                log_area.insert(tk.END, f"{ip} -> {count}\n")

            # -------- Top URLs --------
            log_area.insert(tk.END, "\n🌐 Top URLs:\n")
            for url, count in result["top_urls"]:
                log_area.insert(tk.END, f"{url} -> {count}\n")

            # -------- Status Codes --------
            log_area.insert(tk.END, "\n📡 Status Codes:\n")
            for code, count in result["status_codes"].items():
                log_area.insert(tk.END, f"{code} -> {count}\n")

            # -------- Suspicious --------
            log_area.insert(tk.END, "\n⚠️ Suspicious IPs:\n")
            for ip, count in result["suspicious"]:
                log_area.insert(tk.END, f"{ip} -> {count}\n")

            # -------- Attackers --------
            log_area.insert(tk.END, "\n🚨 Attackers:\n")
            for ip, count in result["attackers"]:
                log_area.insert(tk.END, f"{ip} -> {count} 🚨\n")

            if not result["attackers"]:
                log_area.insert(tk.END, "No major attacks detected\n")

            status.config(
                text=f"Status: Analysis Done | {datetime.now().strftime('%H:%M:%S')}"
            )

        root.after(0, update_ui)

    except Exception as e:
        root.after(0, lambda: status.config(text=f"Error: {e}"))

# -------- Chart Function --------
def show_chart():
    if not last_result:
        status.config(text="⚠️ Run analysis first!")
        return

    ips = [ip for ip, _ in last_result["top_ips"]]
    values = [count for _, count in last_result["top_ips"]]

    plt.figure()
    plt.bar(ips, values)
    plt.title("Top IP Activity")
    plt.xlabel("IP Address")
    plt.ylabel("Requests")
    plt.show()

# -------- File Loader --------
def open_file():
    file_path = filedialog.askopenfilename()

    if file_path:
        status.config(text="Status: Analyzing...")
        threading.Thread(target=analyze_logs, args=(file_path,)).start()

# -------- Buttons --------
tk.Button(root,
          text="📂 Load Log File",
          command=open_file,
          bg=ACCENT,
          fg="black",
          font=("Arial", 12, "bold"),
          relief="flat").pack(pady=10)

tk.Button(root,
          text="📊 Show Chart",
          command=show_chart,
          bg="#38bdf8",
          fg="black",
          font=("Arial", 11, "bold")).pack(pady=5)

# -------- Run --------
root.mainloop()
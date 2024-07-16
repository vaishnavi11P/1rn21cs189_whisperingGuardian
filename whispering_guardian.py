import os
import shutil
import pandas as pd
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext


# Function to scan the directory
def scan_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            yield file_path


# Function to load malware signatures from a file
def load_signatures(file_path):
    with open(file_path, 'r') as file:
        signatures = file.read().splitlines()
    return signatures


# Function to scan a file for malware signatures
def scan_file(file_path, signatures):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            for signature in signatures:
                if signature.encode() in content:
                    return True
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return False


# Function to log suspicious files to a CSV file
def log_suspicious_files(log_file, suspicious_files):
    df = pd.DataFrame(suspicious_files, columns=['File Path'])
    df['Detection Time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    df.to_csv(log_file, index=False)


# Function to quarantine suspicious files
def quarantine_file(file_path, quarantine_dir):
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)
    shutil.move(file_path, os.path.join(quarantine_dir, os.path.basename(file_path)))


# Function to handle scanning process
def run_scan():
    directory = filedialog.askdirectory()
    if not directory:
        return

    results.delete(1.0, tk.END)
    status_label.config(text="Scanning...")
    root.update_idletasks()

    suspicious_files = []
    signatures = load_signatures('signatures.txt')

    for file_path in scan_directory(directory):
        if scan_file(file_path, signatures):
            suspicious_files.append(file_path)
            quarantine = messagebox.askyesno("Quarantine", f"Do you want to quarantine {file_path}?")
            if quarantine:
                quarantine_file(file_path, quarantine_dir)

    log_suspicious_files('suspicious_files_log.csv', suspicious_files)

    if suspicious_files:
        results.insert(tk.END, "Suspicious files found:\n")
        for file_path in suspicious_files:
            results.insert(tk.END, f"{file_path}\n")
    else:
        results.insert(tk.END, "No suspicious files found.")

    status_label.config(text="Scan complete.")


# Create GUI
root = tk.Tk()
root.title("Malware Detection System")

frame = tk.Frame(root)
frame.pack(pady=10)

scan_button = tk.Button(frame, text="Scan Directory", command=run_scan, font=('Arial', 14))
scan_button.pack(pady=5)

results_label = tk.Label(frame, text="Scan Results:", font=('Arial', 12))
results_label.pack(pady=5)

results = scrolledtext.ScrolledText(frame, width=80, height=20, font=('Arial', 10))
results.pack(pady=5)

status_label = tk.Label(root, text="", font=('Arial', 10), fg="blue")
status_label.pack(pady=5)

quarantine_dir = os.path.join(os.getcwd(), 'quarantine')

root.mainloop()
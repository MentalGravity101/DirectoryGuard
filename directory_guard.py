import os
import time
import sqlite3
import argparse
from threading import Event
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox, Toplevel
import sys

DB_FILE = "file_monitor_logs.db"

def initialize_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,
            path TEXT,
            change_type TEXT,
            size_before TEXT,
            size_after TEXT
        )
    """)
    conn.commit()
    conn.close()

class FileChangeHandler(FileSystemEventHandler):

    def log_event(self, event, change_type):
        try:
            source = "Directory" if event.is_directory else "File"
            file_path = event.src_path
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            size_before = os.path.getsize(file_path) if os.path.exists(file_path) else "N/A"
            size_after = "N/A" if change_type == "Deleted" else os.path.getsize(file_path)

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO logs (timestamp, source, path, change_type, size_before, size_after)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (timestamp, source, file_path, change_type, size_before, size_after))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error logging event: {e}")

    def on_modified(self, event):
        try:
            self.log_event(event, "Modified")
        except Exception as e:
            print(f"Error handling modified event: {e}")

    def on_created(self, event):
        try:
            self.log_event(event, "Created")
        except Exception as e:
            print(f"Error handling created event: {e}")

    def on_deleted(self, event):
        try:
            self.log_event(event, "Deleted")
        except Exception as e:
            print(f"Error handling deleted event: {e}")

    def on_moved(self, event):
        try:
            self.log_event(event, "Moved")
        except Exception as e:
            print(f"Error handling moved event: {e}")


def monitor_path(path):
    """Monitors the given file or directory."""
    if not os.path.exists(path):
        print(f"Error: Path '{path}' does not exist.")
        return

    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    print(f"Monitoring '{path}' for changes... (Press Ctrl+C to stop)")

    try:
        stop_event = Event()
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping monitoring...")
        observer.stop()

    observer.join()


def display_log(filter_by=None, value=None):
    """Displays the logged changes with optional filters."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    query = "SELECT * FROM logs"
    params = ()

    if filter_by and value:
        query += f" WHERE {filter_by} = ?"
        params = (value,)

    cursor.execute(query + " ORDER BY timestamp DESC", params)
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("No changes detected.")
        return

    print("\nDetected Changes:")
    for row in rows:
        _, timestamp, source, path, change_type, size_before, size_after = row
        print(f"- Time: {timestamp}")
        print(f"  Source: {source}")
        print(f"  Path: {path}")
        print(f"  Change Type: {change_type}")
        print(f"  Size Before: {size_before}")
        print(f"  Size After: {size_after}")
        print("-" * 40)

def cleanup_logs(older_than_days):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    threshold_time = time.time() - (older_than_days * 86400)
    threshold_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(threshold_time))
    cursor.execute("DELETE FROM logs WHERE timestamp < ?", (threshold_date,))
    conn.commit()
    conn.close()
    print(f"Logs older than {older_than_days} days have been deleted.")

class FileMonitorApp(ttk.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("File and Directory Monitor")
        self.geometry("800x600")  # Increased window size

        self.observer = Observer()
        self.monitored_directories = []  # List of directories being monitored

        # GUI Widgets
        self.create_widgets()

    def create_widgets(self):
        monitor_frame = ttk.Labelframe(self, text="Directory Monitoring", padding=10)
        monitor_frame.pack(fill=X, padx=10, pady=10)

        ttk.Label(monitor_frame, text="Monitor Path:", anchor=W).pack(fill=X, pady=5)
        self.monitor_path_entry = ttk.Entry(monitor_frame)
        self.monitor_path_entry.pack(fill=X, pady=5)

        ttk.Button(monitor_frame, text="Browse", command=self.browse_path).pack(side=LEFT, padx=5, pady=5)
        ttk.Button(monitor_frame, text="Start Monitoring", command=self.start_monitoring, bootstyle="success").pack(side=LEFT, padx=5, pady=5)
        ttk.Button(monitor_frame, text="Stop Monitoring", command=self.stop_monitoring, bootstyle="danger").pack(side=LEFT, padx=5, pady=5)

        file_ops_frame = ttk.Labelframe(self, text="File Operations", padding=10)
        file_ops_frame.pack(fill=X, padx=10, pady=10)

        ttk.Button(file_ops_frame, text="Export Directories List", command=self.export_directories, bootstyle="warning").pack(side=LEFT, padx=5, pady=5)
        ttk.Button(file_ops_frame, text="Import Directories List", command=self.import_directories, bootstyle="primary").pack(side=LEFT, padx=5, pady=5)

        logs_frame = ttk.Labelframe(self, text="Logs", padding=10)
        logs_frame.pack(fill=X, padx=10, pady=10)

        ttk.Button(logs_frame, text="View Logs", command=self.open_logs_window, bootstyle="info").pack(side=LEFT, padx=5, pady=5)

    
        status_frame = ttk.Labelframe(self, text="Currently Monitored Directories", padding=10)
        status_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

        self.monitored_label = ttk.Label(status_frame, text="None", anchor=W, justify=LEFT)
        self.monitored_label.pack(fill=BOTH, expand=True, pady=10)

    def browse_path(self):
        path = filedialog.askdirectory()
        if path:
            self.monitor_path_entry.delete(0, END)
            self.monitor_path_entry.insert(0, path)

    def start_monitoring(self):
        path = self.monitor_path_entry.get()
        if not os.path.exists(path):
            messagebox.showerror("Error", f"Path '{path}' does not exist.")
            return

        
        if path in self.monitored_directories:
            messagebox.showinfo("Already Monitoring", f"The directory '{path}' is already being monitored.")
            return

        try:
            event_handler = FileChangeHandler()
            self.observer.schedule(event_handler, path, recursive=True)
            self.monitored_directories.append(path)
            self.update_monitored_label()

            if not self.observer.is_alive():
                self.observer.start()

            messagebox.showinfo("Monitoring", f"Started monitoring '{path}'")
        except PermissionError:
            messagebox.showerror("Permission Denied", f"Permission denied for directory '{path}'.")
        except RuntimeError as e:
            if "threads can only be started once" in str(e):
                # Create a new observer if the old one has already stopped
                self.observer = Observer()
                self.start_monitoring()
            else:
                messagebox.showerror("Error", f"An unexpected error occurred: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def stop_monitoring(self):
        if not self.monitored_directories:
            messagebox.showinfo("Nothing to Stop", "No directories are currently being monitored.")
            return

        try:
            self.observer.stop()
            self.observer.join()
            self.observer = Observer() 
            self.monitored_directories = []
            self.update_monitored_label()

            messagebox.showinfo("Monitoring", "Stopped monitoring all directories.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while stopping monitoring: {e}")

    def export_directories(self):
        if not self.monitored_directories:
            messagebox.showinfo("Export Failed", "No directories to export.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Export Directories",
            defaultextension=".txt",
            filetypes=(("Text Files", "*.txt"), ("All Files", "*.*"))
        )
        if file_path:
            try:
                with open(file_path, "w") as file:
                    file.write("\n".join(self.monitored_directories))
                messagebox.showinfo("Export Successful", f"Directories exported to '{file_path}'")
            except Exception as e:
                messagebox.showerror("Export Failed", f"An error occurred: {e}")

    def import_directories(self):
        file_path = filedialog.askopenfilename(
            title="Import Directories",
            filetypes=(("Text Files", "*.txt"), ("All Files", "*.*"))
        )
        if not file_path:
            return

        try:
            with open(file_path, "r") as file:
                directories = file.read().splitlines()

            new_directories = []
            for path in directories:
                if not os.path.exists(path):
                    messagebox.showerror("Invalid Directory", f"The directory '{path}' does not exist.")
                    continue
                if path in self.monitored_directories:
                    messagebox.showinfo("Already Monitoring", f"The directory '{path}' is already being monitored.")
                    continue
 
                event_handler = FileChangeHandler()
                self.observer.schedule(event_handler, path, recursive=True)
                new_directories.append(path)

            self.monitored_directories.extend(new_directories)

            self.update_monitored_label()

            if new_directories and not self.observer.is_alive():
                self.observer.start()

            if new_directories:
                messagebox.showinfo("Import Successful", f"Imported and monitoring new directories:\n{', '.join(new_directories)}")
            else:
                messagebox.showinfo("Import Complete", "No new directories were added.")
        except Exception as e:
            messagebox.showerror("Import Failed", f"An error occurred: {e}")

    def update_monitored_label(self):
        if not self.monitored_directories:
            self.monitored_label.config(text="None")
        else:
            directories = "\n".join(self.monitored_directories)
            self.monitored_label.config(text=directories)

    def open_logs_window(self):
        LogsWindow(self)


class LogsWindow(Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("View Logs")
        try:
            self.state("zoomed")
        except:
            screen_width = self.winfo_screenwidth()
            screen_height = self.winfo_screenheight()
            self.geometry(f"{screen_width}x{screen_height}")

        style = ttk.Style()
        style.configure("Treeview", rowheight=25)  # Adjust row height for better visibility
        style.configure("Treeview.Heading", anchor=CENTER)  # Center column headings

        search_frame = ttk.Frame(self, padding=10)
        search_frame.pack(fill=X, pady=10)

        ttk.Label(search_frame, text="Search:", anchor=W).pack(side=LEFT, padx=5)
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side=LEFT, fill=X, expand=True, padx=5)
        ttk.Button(search_frame, text="Search", command=self.search_logs, bootstyle="info").pack(side=LEFT, padx=5)
        ttk.Button(search_frame, text="Refresh", command=self.load_logs, bootstyle="primary").pack(side=LEFT, padx=5)

        tree_frame = ttk.Frame(self, padding=10)
        tree_frame.pack(fill=BOTH, expand=True, pady=10)

        y_scrollbar = ttk.Scrollbar(tree_frame, orient=VERTICAL)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("Timestamp", "Source", "Path", "Change Type", "Size Before", "Size After"),
            show="headings",
            yscrollcommand=y_scrollbar.set,
        )

        self.tree.heading("Timestamp", text="Timestamp", anchor=CENTER)
        self.tree.heading("Source", text="Source", anchor=CENTER)
        self.tree.heading("Path", text="Path", anchor=CENTER)
        self.tree.heading("Change Type", text="Change Type", anchor=CENTER)
        self.tree.heading("Size Before", text="Size Before", anchor=CENTER)
        self.tree.heading("Size After", text="Size After", anchor=CENTER)

        self.tree.column("Timestamp", anchor=CENTER, width=150)
        self.tree.column("Source", anchor=CENTER, width=100)
        self.tree.column("Path", anchor=CENTER, width=300)
        self.tree.column("Change Type", anchor=CENTER, width=100)
        self.tree.column("Size Before", anchor=CENTER, width=100)
        self.tree.column("Size After", anchor=CENTER, width=100)

        y_scrollbar.config(command=self.tree.yview)

        self.tree.pack(side=LEFT, fill=BOTH, expand=True)
        y_scrollbar.pack(side=RIGHT, fill=Y)

        self.load_logs()

    def load_logs(self):
        self.tree.delete(*self.tree.get_children())
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            self.tree.insert("", END, values=row[1:])  # Exclude ID from display

    def search_logs(self):
        query = self.search_entry.get().strip()

        self.tree.delete(*self.tree.get_children())
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        if query:
            sql_query = """
                SELECT * FROM logs
                WHERE timestamp LIKE ? OR source LIKE ? OR path LIKE ? OR change_type LIKE ?
            """
            cursor.execute(sql_query, (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%"))
        else:
            cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC")

        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            self.tree.insert("", END, values=row[1:])
def main():
    initialize_database()
    if len(sys.argv) == 1:
        app = FileMonitorApp()
        app.mainloop()
    else:
        parser = argparse.ArgumentParser(description="File and Directory Change Monitor")
        parser.add_argument("command", choices=["monitor", "log", "cleanup"], help="Command for CLI mode")
        parser.add_argument("--path", help="Path to monitor (required for 'monitor')")
        parser.add_argument("--filter", choices=["source", "change_type"], help="Filter logs by this field")
        parser.add_argument("--value", help="Value for the filter field")
        parser.add_argument("--older_than_days", type=int, help="Delete logs older than specified days (for cleanup)")

        args = parser.parse_args()

        if args.command == "monitor" and args.path:
            monitor_path(args.path)
        elif args.command == "log":
            display_log(filter_by=args.filter, value=args.value)
        elif args.command == "cleanup" and args.older_than_days:
            cleanup_logs(args.older_than_days)
        else:
            print("Invalid CLI arguments. Use '--help' for usage details.")

if __name__ == "__main__":
    main()

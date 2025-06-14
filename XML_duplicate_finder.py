import os
import mmh3
import threading
from concurrent.futures import ThreadPoolExecutor
import re
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk, messagebox
import sys
import queue
import traceback
import ctypes

def get_file_hash(file_path):
    """Find MurmurHash3 hash of a file's content."""
    with open(file_path, 'rb') as file:
        content = file.read()
        return mmh3.hash_bytes(content)

def extract_filename_info(filename):
    """Extract P number and timestamp information from the filename."""
    # Pattern for P number extraction
    p_pattern = r'(\d+)P(_\d+)+(\([A-Za-z]+\))*(.*\.xml)'
    # Pattern for timestamp extraction
    timestamp_pattern = r'^.*(\d{14}_\d).*$'
    
    # Try to extract P number
    p_match = re.match(p_pattern, filename)
    p_number = None
    if p_match:
        p_number = int(p_match.group(1))
    
    # Try to extract timestamp
    timestamp_match = re.match(timestamp_pattern, filename)
    timestamp = None
    if timestamp_match:
        timestamp = timestamp_match.group(1)
    else:
        # Fallback to the old timestamp pattern if new one doesn't match
        old_match = re.search(r'(\d{14})', filename)
        if old_match:
            timestamp = old_match.group(1)
    
    return {
        'p_number': p_number,
        'timestamp': timestamp,
        'has_p_number': p_number is not None
    }

def find_xml_files(root_dir):
    """Find all XML files in the directory."""
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.lower().endswith('.xml'):
                yield os.path.join(dirpath, filename)

def scan_for_duplicates(root_dir, max_threads=16, progress_callback=None, log_callback=None):
    """Scan for duplicate XML files and return a dictionary of hash to file list."""
    seen_hashes = {}
    lock = threading.Lock()
    file_count = 0
    processed_count = 0
    
    # First count the total number of XML files
    if log_callback:
        log_callback(f"\nScanning '{root_dir}' for duplicate XML files...\n")
    
    # Get total file count first for progress tracking
    xml_files = list(find_xml_files(root_dir))
    file_count = len(xml_files)
    
    if file_count == 0:
        if log_callback:
            log_callback("No XML files found in the selected directory.")
        return {}
    
    def process_file(xml_file):
        nonlocal processed_count
        try:
            file_hash = get_file_hash(xml_file)
            with lock:
                if file_hash in seen_hashes:
                    seen_hashes[file_hash].append(xml_file)
                else:
                    seen_hashes[file_hash] = [xml_file]
                processed_count += 1
                if progress_callback and file_count > 0:
                    progress_callback(processed_count / file_count * 100)
        except Exception as e:
            if log_callback:
                log_callback(f"Error processing {xml_file}: {str(e)}")

    with ThreadPoolExecutor(max_threads) as executor:
        executor.map(process_file, xml_files)

    # Filter out hashes with only one file
    duplicates = {hash_value: file_list for hash_value, file_list in seen_hashes.items() if len(file_list) > 1}
    return duplicates

def delete_file(file_path, log_callback=None):
    """Delete the picked file."""
    try:
        os.remove(file_path)
        if log_callback:
            log_callback(f"[DELETED] {file_path}")
    except Exception as e:
        if log_callback:
            log_callback(f"Error deleting {file_path}: {e}")

def resolve_duplicates(duplicate_files, log_callback=None, dry_run=False):
    """
    Resolve duplicates with the following priority:
    1. Keep files with higher P numbers
    2. Keep files with P numbers over those without
    3. Keep files with older timestamps
    """
    if not duplicate_files or len(duplicate_files) < 2:
        return []

    files_with_info = []
    for file_path in duplicate_files:
        filename = os.path.basename(file_path)
        file_info = extract_filename_info(filename)
        files_with_info.append((file_path, file_info))
    
    # Group files by whether they have P numbers
    files_with_p = [f for f in files_with_info if f[1]['has_p_number']]
    files_without_p = [f for f in files_with_info if not f[1]['has_p_number']]
    
    # If we have files with P numbers, prioritize those
    if files_with_p:
        # Sort by P number (higher is better)
        files_with_p.sort(key=lambda item: item[1]['p_number'] if item[1]['p_number'] is not None else -1, reverse=True)
        
        # Keep the file with the highest P number
        file_to_keep = files_with_p[0]
        files_to_delete = files_with_p[1:] + files_without_p
    else:
        # If no files have P numbers, sort by timestamp (older is better)
        valid_timestamp_files = [f for f in files_without_p if f[1]['timestamp']]
        
        if valid_timestamp_files:
            valid_timestamp_files.sort(key=lambda item: item[1]['timestamp'])
            file_to_keep = valid_timestamp_files[0]
            files_to_delete = valid_timestamp_files[1:] + [f for f in files_without_p if not f[1]['timestamp']]
        else:
            if log_callback:
                log_callback("Warning: Could not extract timestamp from any filename. Skipping deletion.")
            return []
    
    # Log information about the files
    if log_callback:
        log_callback(f"\nDuplicate files found:")
        for file_path, info in files_with_info:
            p_info = f"P Number: {info['p_number']}" if info['has_p_number'] else "No P Number"
            timestamp_info = f"Timestamp: {info['timestamp']}" if info['timestamp'] else "No Timestamp"
            log_callback(f" - {file_path} ({p_info}, {timestamp_info})")
        
        log_callback(f"\nKeeping file with {'highest P number' if files_with_p else 'oldest timestamp'}:")
        p_info = f"P Number: {file_to_keep[1]['p_number']}" if file_to_keep[1]['has_p_number'] else "No P Number"
        timestamp_info = f"Timestamp: {file_to_keep[1]['timestamp']}" if file_to_keep[1]['timestamp'] else "No Timestamp"
        log_callback(f" - {file_to_keep[0]} ({p_info}, {timestamp_info})")
    
    deleted_files = []
    if files_to_delete:
        if log_callback:
            log_callback("\nFiles to delete:")
        for file_path, info in files_to_delete:
            p_info = f"P Number: {info['p_number']}" if info['has_p_number'] else "No P Number"
            timestamp_info = f"Timestamp: {info['timestamp']}" if info['timestamp'] else "No Timestamp"
            if log_callback:
                log_callback(f" - {file_path} ({p_info}, {timestamp_info})")
            
            if not dry_run:
                delete_file(file_path, log_callback)
            deleted_files.append(file_path)
    else:
        if log_callback:
            log_callback("No files to delete.")
    
    return deleted_files

class RedirectText:
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.queue = queue.Queue()
        self.updating = True
        self.update()
    
    def write(self, string):
        self.queue.put(string)
    
    def flush(self):
        pass
    
    def update(self):
        try:
            while True:
                # Get from queue without blocking
                text = self.queue.get_nowait()
                self.text_widget.configure(state='normal')
                self.text_widget.insert(tk.END, text)
                self.text_widget.see(tk.END)  # Auto-scroll to the end
                self.text_widget.configure(state='disabled')
                self.queue.task_done()
        except queue.Empty:
            if self.updating:
                self.text_widget.after(100, self.update)
    
    def stop_updating(self):
        self.updating = False

class XMLDuplicateFinderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("XML Duplicate Finder")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Set Arial font as default
        default_font = ("Arial", 10)
        
        # Set application icon if available
        try:
            # Check if we're running as a bundled app or as a script
            if getattr(sys, 'frozen', False):
                application_path = sys._MEIPASS
            else:
                application_path = os.path.dirname(os.path.abspath(__file__))
            icon_path = os.path.join(application_path, "icon.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass  # Skip icon if not available
        
        # Create a frame for the directory selection
        self.dir_frame = ttk.Frame(root, padding="10")
        self.dir_frame.pack(fill=tk.X)
        
        # Directory selection
        ttk.Label(self.dir_frame, text="Directory:").pack(side=tk.LEFT, padx=(0, 5))
        self.dir_var = tk.StringVar()
        self.dir_entry = ttk.Entry(self.dir_frame, textvariable=self.dir_var, width=50)
        self.dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(self.dir_frame, text="Browse", command=self.browse_directory).pack(side=tk.LEFT)
        
        # Create a frame for the action buttons
        self.button_frame = ttk.Frame(root, padding="10")
        self.button_frame.pack(fill=tk.X)
        
        # Action buttons
        self.delete_button = ttk.Button(self.button_frame, text="Delete Duplicates", command=self.delete_duplicates)
        self.delete_button.pack(side=tk.LEFT)
        self.delete_button.config(state=tk.DISABLED)  # Disabled until scan is complete
        
        # Progress bar
        self.progress_frame = ttk.Frame(root, padding="10")
        self.progress_frame.pack(fill=tk.X)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X)
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(self.progress_frame, textvariable=self.status_var)
        self.status_label.pack(anchor=tk.W, pady=(5, 0))
        
        # Log text area
        self.log_frame = ttk.LabelFrame(root, text="Log", padding="10")
        self.log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD, state='disabled')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Redirect stdout to the text widget
        self.text_redirect = RedirectText(self.log_text)
        sys.stdout = self.text_redirect
        
        # Store scan results
        self.duplicate_files_by_hash = {}
        
        # Set up thread event to signal cancellation
        self.cancel_event = threading.Event()
        
        # Bind close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Show welcome message
        self.log("Welcome to XML Duplicate Finder!")
        self.log("Select a directory and click 'Scan for Duplicates' to begin.")
    
    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dir_var.set(directory)
            # Check for GodPacks subfolder
            self.check_for_godpacks(directory)
            # Automatically start scanning after directory selection
            self.scan_directory()
    
    def check_for_godpacks(self, directory):
        """Check if the directory or any of its subdirectories contains a folder named 'GodPacks'."""
        try:
            for root, dirs, _ in os.walk(directory):
                if "GodPacks" in dirs:
                    messagebox = tk.messagebox.showwarning(
                        "Warning", 
                        "Warning: God Pack Accounts already exist in your Saved Accounts folder. " +
                        "It is recommended to ONLY browse in the \"Saved\" or \"Account Vault\" folder"
                    )
                    break
        except Exception as e:
            print(f"Error checking for GodPacks: {e}")
    
    def log(self, message):
        # Log to the text widget
        print(message)
    
    def update_progress(self, value):
        self.progress_var.set(value)
        self.root.update_idletasks()
    
    def update_status(self, status):
        self.status_var.set(status)
        self.root.update_idletasks()
    
    def scan_directory(self):
        directory = self.dir_var.get()
        if not directory or not os.path.isdir(directory):
            self.log("❌ Please select a valid directory.")
            return
        
        # Disable delete button during scan
        self.delete_button.config(state=tk.DISABLED)
        self.update_status("Scanning...")
        self.progress_var.set(0)
        
        # Clear previous results
        self.duplicate_files_by_hash = {}
        
        # Reset and clear log
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state='disabled')
        
        # Start scanning in a separate thread
        threading.Thread(target=self._scan_thread, args=(directory,), daemon=True).start()
    
    def _scan_thread(self, directory):
        try:
            self.log(f"Scanning directory: {directory}")
            self.duplicate_files_by_hash = scan_for_duplicates(
                directory, 
                progress_callback=self.update_progress,
                log_callback=self.log
            )
            
            # Update UI with results
            self.root.after(0, self._update_ui_after_scan)
        except Exception as e:
            self.log(f"Error during scan: {str(e)}")
            self.log(traceback.format_exc())
            self.root.after(0, self._reset_ui_after_error)
    
    def _update_ui_after_scan(self):
        if self.duplicate_files_by_hash:
            total_duplicates = sum(len(file_list) - 1 for file_list in self.duplicate_files_by_hash.values())
            self.log(f"\n🔍 Found {len(self.duplicate_files_by_hash)} sets of duplicate XML files ({total_duplicates} total duplicates)")
            
            for hash_value, file_list in self.duplicate_files_by_hash.items():
                self.log(f"\nDuplicate set:")
                for file_path in file_list:
                    self.log(f" - {file_path}")
            
            self.delete_button.config(state=tk.NORMAL)
            self.update_status(f"Found {total_duplicates} duplicate files in {len(self.duplicate_files_by_hash)} sets")
        else:
            self.log("\n✅ No duplicate XML files found.")
            self.update_status("No duplicates found")
        
        self.progress_var.set(100)
    
    def _reset_ui_after_error(self):
        self.delete_button.config(state=tk.DISABLED)
        self.update_status("Error during scan")
    
    def delete_duplicates(self):
        if not self.duplicate_files_by_hash:
            self.log("No duplicates to delete.")
            return
        
        # Calculate total number of files to be deleted
        total_duplicates = sum(len(file_list) - 1 for file_list in self.duplicate_files_by_hash.values())
        
        # Show confirmation dialog
        confirm = messagebox.askokcancel(
            "Confirm Deletion",
            f"Are you sure you want to delete {total_duplicates} duplicate files?\n\n" +
            "This action cannot be undone."
        )
        
        if not confirm:
            self.log("Deletion cancelled by user.")
            return
        
        # Disable delete button during deletion
        self.delete_button.config(state=tk.DISABLED)
        
        self.update_status("Deleting duplicates...")
        
        # Start deletion in a separate thread
        threading.Thread(target=self._delete_thread, args=(False,), daemon=True).start()
    
    def _delete_thread(self, is_dry_run):
        try:
            total_deleted = 0
            total_sets = len(self.duplicate_files_by_hash)
            current_set = 0
            
            for hash_value, file_list in self.duplicate_files_by_hash.items():
                if self.cancel_event.is_set():
                    self.log("Operation cancelled.")
                    break
                
                self.log(f"\nProcessing duplicate set {current_set + 1} of {total_sets}:")
                deleted_files = resolve_duplicates(file_list, self.log, is_dry_run)
                total_deleted += len(deleted_files)
                current_set += 1
                
                # Update progress
                self.root.after(0, lambda: self.update_progress(current_set / total_sets * 100))
            
            # Update UI after completion
            self.root.after(0, lambda: self._update_ui_after_deletion(total_deleted, is_dry_run))
        except Exception as e:
            self.log(f"Error during deletion: {str(e)}")
            self.log(traceback.format_exc())
            self.root.after(0, self._reset_ui_after_error)
    
    def _update_ui_after_deletion(self, total_deleted, was_dry_run):
        self.log(f"\n✅ Duplicate XML removal process completed. {total_deleted} files deleted.")
        self.update_status(f"Completed: {total_deleted} files deleted")
        
        # Reset UI
        self.delete_button.config(state=tk.NORMAL)
        self.progress_var.set(100)
    
    def on_closing(self):
        # Signal threads to stop
        self.cancel_event.set()
        
        # Stop the text redirect update loop
        if hasattr(self, 'text_redirect'):
            self.text_redirect.stop_updating()
        
        # Restore stdout
        sys.stdout = sys.__stdout__
        
        # Close the window
        self.root.destroy()

# Add DPI awareness for Windows
def set_dpi_awareness():
    """Set DPI awareness to ensure the application displays correctly on high-DPI screens."""
    try:
        if sys.platform == 'win32':
            # Try the Windows 10 way first
            awareness = ctypes.c_int()
            errorCode = ctypes.windll.shcore.GetProcessDpiAwareness(0, ctypes.byref(awareness))
            
            if errorCode == 0:  # Success
                # If not already DPI aware, set it
                if awareness.value != 2:  # PROCESS_PER_MONITOR_DPI_AWARE
                    ctypes.windll.shcore.SetProcessDpiAwareness(2)  # PROCESS_PER_MONITOR_DPI_AWARE
            else:
                # Fall back to the Windows 8.1 and earlier way
                ctypes.windll.user32.SetProcessDPIAware()
    except Exception as e:
        print(f"Error setting DPI awareness: {e}")

if __name__ == "__main__":
    try:
        # Set DPI awareness before creating the window
        set_dpi_awareness()
        
        # Set up the root window
        root = tk.Tk()
        app = XMLDuplicateFinderApp(root)
        root.mainloop()
    except Exception as e:
        # If we get an exception during startup, show it in a message box
        import traceback
        error_msg = f"Error: {str(e)}\n\n{traceback.format_exc()}"
        
        try:
            # Try to show a tkinter error dialog
            import tkinter.messagebox as messagebox
            messagebox.showerror("Error", error_msg)
        except:
            # If that fails, fall back to console
            print(error_msg)
VERSION = 1.000
import os, sys, ctypes
import tkinter as tk
from tkinter import messagebox

def check_for_windows_os():
    current_platform = sys.platform
    if not current_platform == "win32":
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Unsupported Platform", "This program can only run on Windows.")
        sys.exit()

def check_for_npcap_installation():
    npcap_driver_path = os.path.join(os.getenv('windir'), 'system32', 'drivers', 'npcap.sys')
    if not os.path.exists(npcap_driver_path):
        root = tk.Tk()
        root.withdraw()
        if messagebox.askyesno("Npcap Required", "Npcap is required to use this program.\n\nWould you like to download it now?"):
            messagebox.showinfo("Exiting", "The program will now exit and open the Npcap download webpage.")
            import webbrowser
            webbrowser.open("https://npcap.com/#download")
        else: 
            messagebox.showinfo("Exiting", "The program will now exit.")
        sys.exit()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join([f'"{x}"' for x in sys.argv]), None, 1)
    sys.exit()

check_for_windows_os()
check_for_npcap_installation()

if not is_admin():
    run_as_admin()

import time
from pathlib import Path
import subprocess
import threading
from collections import defaultdict
import configparser
from scapy.all import sniff, IP, get_if_addr, get_if_list, conf
import pyperclip

ip_counter = defaultdict(int)
sniffing_active = True
ip_address = None
network_interface = None
capture_device_ip = None

if getattr(sys, 'frozen', False):
    script_dir = os.path.dirname(sys.executable)
else:
    script_dir = os.path.dirname(os.path.abspath(__file__))

def load_config():
    config = configparser.ConfigParser()
    config_path = Path(script_dir) / 'config.ini'
    
    config_template = """[Settings]
# REQUIRED SETTINGS:
PROTOCOL = UDP               # Protocol to monitor (UDP/TCP)
PORT =                       # Port number to monitor
FOUND_PACKETS_REQUIRED = 25  # Number of packets to confirm match
TIMEOUT_SECONDS = 5          # Timeout in seconds for detection

# OPTIONAL SETTINGS:
FIREWALL_RULE_BASENAME =     # Optional prefix for final firewall rule name
ADDITIONAL_BPF_FILTER =      # Optional additional BPF filter rules
NETWORK_INTERFACE =          # Network interface name (leave blank for selection)
"""
    
    if not config_path.exists():
        with open(config_path, 'w') as f:
            f.write(config_template)
        
        messagebox.showinfo(
            "Configuration Created",
            f"Config file created at:\n{config_path}\n\n"
            "Please review settings before running."
        )
        sys.exit(0)
    
    # Read config while preserving case
    config = configparser.ConfigParser()
    config.optionxform = str  # Preserve case
    config.read(config_path)
    
    # Clean values by removing comments and whitespace
    def clean_value(value):
        if not isinstance(value, str):
            return value
        return value.split('#')[0].strip()
    
    # Get all settings with cleaning
    settings = {}
    for key in config['Settings']:
        settings[key] = clean_value(config['Settings'][key])
    
    # Validate required fields
    missing_fields = []
    if not settings.get('PROTOCOL'):
        missing_fields.append("PROTOCOL")
    if not settings.get('PORT'):
        missing_fields.append("PORT")
    
    if missing_fields:
        messagebox.showerror(
            "Configuration Error",
            f"Required settings missing in config:\n{', '.join(missing_fields)}\n\n"
            f"Please edit {config_path} and fill in all required settings."
        )
        sys.exit(1)
    
    # Validate protocol is either TCP or UDP
    protocol = settings['PROTOCOL'].upper()
    if protocol not in ('TCP', 'UDP'):
        messagebox.showerror(
            "Configuration Error",
            f"Invalid PROTOCOL in config. Must be either TCP or UDP.\n\n"
            f"Please edit {config_path} and correct the PROTOCOL setting."
        )
        sys.exit(1)
    settings['PROTOCOL'] = protocol
    
     # Validate port is an integer and in valid range
    try:
        port = int(settings['PORT'])
        if not (1 <= port <= 65535):
            raise ValueError
        settings['PORT'] = str(port)
    except Exception:
        messagebox.showerror(
            "Configuration Error",
            f"Invalid PORT in config. Must be an integer between 1 and 65535.\n\n"
            f"Please edit {config_path} and correct the PORT setting."
        )
        sys.exit(1)

    # Validate numeric fields
    try:
        settings['FOUND_PACKETS_REQUIRED'] = int(settings['FOUND_PACKETS_REQUIRED'])
        settings['TIMEOUT_SECONDS'] = int(settings['TIMEOUT_SECONDS'])
    except ValueError as e:
        messagebox.showerror(
            "Configuration Error",
            f"Invalid numeric value in config:\n{str(e)}\n\n"
            f"Please check PORT, FOUND_PACKETS_REQUIRED and TIMEOUT_SECONDS\n"
            f"in {config_path}"
        )
        sys.exit(1)
    
    return settings

def get_friendly_names():
    interfaces = get_if_list()
    friendly_names = []
    for iface in interfaces:
        try:
            import wmi
            wmi_client = wmi.WMI()
            wmi_query = "SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionID != NULL"
            for nic in wmi_client.query(wmi_query):
                if nic.GUID and iface.endswith(nic.GUID):
                    friendly_name = f"{nic.NetConnectionID or nic.Name}"
                    friendly_names.append((iface, friendly_name))
                    break
        except Exception as e:
            friendly_names.append((iface, iface))
    return friendly_names

def select_network_interface():
    try:
        interface_pairs = get_friendly_names()
        if not interface_pairs:
            raise Exception("No network interfaces found!")
        
        root = tk.Tk()
        root.withdraw()
        
        selection = tk.StringVar(root)
        display_names = []
        value_map = {}
        
        for iface, friendly in interface_pairs:
            display = f"{friendly} ({iface})"
            display_names.append(display)
            value_map[display] = iface
        
        selection.set(display_names[0])  # Default to first interface
        
        dialog = tk.Toplevel(root)
        dialog.title("Select Network Interface")
        
        # This will track if the dialog was cancelled
        dialog.user_choice = None
        
        def on_ok():
            dialog.user_choice = value_map[selection.get()]
            dialog.destroy()
            
        def on_cancel():
            dialog.user_choice = None
            dialog.destroy()
            
        def on_close():
            dialog.user_choice = None
            dialog.destroy()
            
        dialog.protocol("WM_DELETE_WINDOW", on_close)
        
        tk.Label(dialog, text="Select network interface:", 
                font=('Arial', 12)).pack(pady=10)
        
        # Create dropdown with only the combined display names
        dropdown = tk.OptionMenu(dialog, selection, *display_names)
        dropdown.config(font=('Arial', 11), width=60)
        dropdown.pack(pady=10, ipady=5)
        
        # Add buttons
        button_frame = tk.Frame(dialog)
        button_frame.pack(pady=15)
        
        ok_button = tk.Button(button_frame, text="OK", command=on_ok,
                            width=10, height=2, font=('Arial', 10))
        ok_button.pack(side=tk.LEFT, padx=5)
        
        cancel_button = tk.Button(button_frame, text="Cancel", command=on_cancel,
                               width=10, height=2, font=('Arial', 10))
        cancel_button.pack(side=tk.LEFT, padx=5)
        
        dialog.wait_window()
        
        return dialog.user_choice
        
    except Exception as e:
        print(f"⚠️ Interface selection error: {e}")
        # Fallback to basic interface names
        interfaces = get_if_list()
        if not interfaces:
            raise Exception("No network interfaces found!")
        
        root = tk.Tk()
        root.withdraw()
        
        selection = tk.StringVar(root)
        selection.set(interfaces[0])
        
        dialog = tk.Toplevel(root)
        dialog.title("Select Network Interface")
        dialog.user_choice = None
        
        def on_ok():
            dialog.user_choice = selection.get()
            dialog.destroy()
            
        def on_cancel():
            dialog.user_choice = None
            dialog.destroy()
            
        def on_close():
            dialog.user_choice = None
            dialog.destroy()
            
        dialog.protocol("WM_DELETE_WINDOW", on_close)
        
        tk.Label(dialog, text="Select network interface:", 
                font=('Arial', 12)).pack(pady=10)
        
        dropdown = tk.OptionMenu(dialog, selection, *interfaces)
        dropdown.config(font=('Arial', 11), width=40)
        dropdown.pack(pady=10, ipady=5)
        
        # Add buttons
        button_frame = tk.Frame(dialog)
        button_frame.pack(pady=15)
        
        ok_button = tk.Button(button_frame, text="OK", command=on_ok,
                            width=10, height=2, font=('Arial', 10))
        ok_button.pack(side=tk.LEFT, padx=5)
        
        cancel_button = tk.Button(button_frame, text="Cancel", command=on_cancel,
                               width=10, height=2, font=('Arial', 10))
        cancel_button.pack(side=tk.LEFT, padx=5)
        
        dialog.wait_window()
        
        return dialog.user_choice
    
def get_network_interface(config):
    if config.get('NETWORK_INTERFACE'):
        return config['NETWORK_INTERFACE']
    
    # If not in config, prompt user to select
    try:
        selected_interface = select_network_interface()
        if selected_interface is None:  # User cancelled
            messagebox.showinfo("Info", "No network interface selected. Exiting.")
            sys.exit(0)
            
        # Save selection to config while preserving comments
        config_path = Path(script_dir) / 'config.ini'
        
        # Read the entire file to preserve comments
        with open(config_path, 'r') as f:
            lines = f.readlines()
        
        # Find and update the NETWORK_INTERFACE line
        updated = False
        for i, line in enumerate(lines):
            if line.strip().startswith('NETWORK_INTERFACE ='):
                lines[i] = f"NETWORK_INTERFACE = {selected_interface}  # Network interface name (leave blank for selection)\n"
                updated = True
                break
        
        # If not found, add it to the end of the [Settings] section
        if not updated:
            for i, line in enumerate(lines):
                if line.strip().startswith('[Settings]'):
                    # Find the end of the [Settings] section
                    j = i + 1
                    while j < len(lines) and not lines[j].strip().startswith('['):
                        j += 1
                    # Insert before the next section or at end
                    lines.insert(j, f"NETWORK_INTERFACE = {selected_interface}  # Network interface name (leave blank for selection)\n")
                    break
        
        # Write the file back with preserved comments
        with open(config_path, 'w') as f:
            f.writelines(lines)
        
        return selected_interface
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to select network interface: {str(e)}")
        sys.exit(1)

def get_firewall_rule_name(parent, initial_value):
    dialog = tk.Toplevel(parent)
    dialog.title("Firewall Rule Name")
    dialog.geometry("400x200")  # Set your desired size here
    
    # Make dialog modal
    dialog.transient(parent)
    dialog.grab_set()
    
    tk.Label(dialog, text="Enter name for the firewall rule:", 
            font=('Arial', 12)).pack(pady=20)
    
    entry_var = tk.StringVar(value=initial_value)
    entry = tk.Entry(dialog, textvariable=entry_var, font=('Arial', 12))
    entry.pack(pady=10, ipady=5, padx=20, fill=tk.X)
    entry.select_range(0, tk.END)  # Select all text for easy replacement
    entry.focus_set()
    
    result = None
    
    def on_ok():
        nonlocal result
        result = entry_var.get().strip()
        dialog.destroy()
    
    def on_cancel():
        nonlocal result
        result = None
        dialog.destroy()
    
    def on_enter_key(event):
        on_ok()
    
    entry.bind('<Return>', on_enter_key)
    
    button_frame = tk.Frame(dialog)
    button_frame.pack(pady=20)
    
    ok_button = tk.Button(button_frame, text="OK", command=on_ok,
                        width=10, height=1, font=('Arial', 10))
    ok_button.pack(side=tk.LEFT, padx=10)
    
    cancel_button = tk.Button(button_frame, text="Cancel", command=on_cancel,
                           width=10, height=1, font=('Arial', 10))
    cancel_button.pack(side=tk.LEFT, padx=10)
    
    # Handle window close button
    dialog.protocol("WM_DELETE_WINDOW", on_cancel)
    
    # Center the dialog
    dialog.update_idletasks()
    x = parent.winfo_x() + (parent.winfo_width() - dialog.winfo_width()) // 2
    y = parent.winfo_y() + (parent.winfo_height() - dialog.winfo_height()) // 2
    dialog.geometry(f"+{x}+{y}")
    
    dialog.wait_window()
    return result

# GUI Manager
class App:
    def __init__(self, root, config):
        self.root = root
        self.config = config
        self.root.title(f"Windows Firewall Spam Blocker v{VERSION}")
        self.root.geometry("400x120")
        
        self.status_frame = tk.Frame(root)
        self.status_frame.pack(expand=True, fill=tk.BOTH)
        
        self.status_label = tk.Label(
            self.status_frame, 
            text="Scanning for IP address...", 
            font=('Arial', 22, 'bold')
        )
        self.status_label.pack(expand=True)
        
        self.action_frame = tk.Frame(root)
        
        self.ip_label = tk.Label(
            self.action_frame, 
            text="", 
            font=('Arial', 22, 'bold')
        )
        self.ip_label.pack(pady=5)
        
        button_frame = tk.Frame(self.action_frame)
        button_frame.pack(pady=5)
        
        self.copy_btn = tk.Button(
            button_frame, 
            text="COPY TO CLIPBOARD", 
            command=self.copy_ip,
            width=18,
            height=2,
            font=('Arial', 12, 'bold')
        )
        self.copy_btn.pack(side=tk.LEFT, padx=5)
        
        self.block_btn = tk.Button(
            button_frame, 
            text="BLOCK IN FIREWALL", 
            command=self.block_ip,
            width=18,
            height=2,
            font=('Arial', 12, 'bold')
        )
        self.block_btn.pack(side=tk.LEFT, padx=5)
    
    def show_found_ip(self, ip):
        self.status_frame.pack_forget()
        self.ip_label.config(text=f"Found IP: {ip}")
        self.action_frame.pack(expand=True, fill=tk.BOTH)
    
    def copy_ip(self):
        pyperclip.copy(ip_address)

    def block_ip(self):
        rule_name = get_firewall_rule_name(root, ip_address)
        
        if rule_name is None:
            return
        
        rule_name = rule_name.strip() or ip_address
        rule_name = f"{self.config['FIREWALL_RULE_BASENAME']} {rule_name}"
        
        cmd = (
            f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block '
            f'protocol={self.config["PROTOCOL"]} localport={self.config["PORT"]} '
            f'remoteip={ip_address} enable=yes & '
            f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block '
            f'protocol={self.config["PROTOCOL"]} localport={self.config["PORT"]} '
            f'remoteip={ip_address} enable=yes'
        )
        
        try:
            subprocess.run(cmd, shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            verify_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
            result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True)
            
            if "No rules match" in result.stdout:
                messagebox.showerror("Error", "Rules created but verification failed")
            else:
                messagebox.showinfo("Success", f"Successfully blocked '{ip_address}'")
                
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to create rules: {e.stderr.decode().strip()}")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {str(e)}")

def check_timeout(timeout_seconds, start_time, app):
    if time.time() - start_time > timeout_seconds:
        global sniffing_active
        sniffing_active = False
        app.status_label.config(text=f"No spam detected!")
        return True
    return False

def packet_callback(packet, found_packets_required, app):
    global sniffing_active, ip_address, capture_device_ip
    
    if IP not in packet:
        return
    
    ip = packet[IP].dst if packet[IP].src == capture_device_ip else packet[IP].src
    ip_counter[ip] += 1
    
    if ip_counter[ip] == found_packets_required:
        ip_address = ip
        sniffing_active = False
        app.show_found_ip(ip)

def create_bpf_filter(protocol, port, additional_filter):
    result = f"{protocol.lower()} port {port}"
    if additional_filter:
        result += f" and {additional_filter}"
    return result

try:
    config = load_config()
    
    if config['ADDITIONAL_BPF_FILTER']:
        # Remove leading "and " or "and" if present
        additional_filter = config['ADDITIONAL_BPF_FILTER'].strip()
        if additional_filter.lower().startswith(("and ", "and")):
            additional_filter = additional_filter[3:].lstrip()  # Remove "and"
        
        try:
            if " and " in additional_filter and not all(term.strip() for term in additional_filter.split(" and ")):
                raise ValueError("Invalid AND condition in filter")
            if " or " in additional_filter and not all(term.strip() for term in additional_filter.split(" or ")):
                raise ValueError("Invalid OR condition in filter")
            
            config['ADDITIONAL_BPF_FILTER'] = additional_filter
        except Exception as e:
            messagebox.showerror(
                "Configuration Error",
                f"Invalid BPF filter syntax:\n{str(e)}\n\n"
                f"Filter being tested: {additional_filter}\n\n"
                f"Please check ADDITIONAL_BPF_FILTER in {Path(script_dir) / 'config.ini'}\n"
                f"or leave it empty if unsure."
            )
            sys.exit(1)
    
    network_interface = get_network_interface(config)
    conf.iface = network_interface
    capture_device_ip = get_if_addr(network_interface)
    
    if not capture_device_ip or capture_device_ip == "0.0.0.0":
        raise ValueError("Could not determine IP for the interface.")
    
    root = tk.Tk()
    app = App(root, config)
    
    def sniff_thread():
        global start_time
        start_time = time.time()
        
        try:
            while sniffing_active:
                if check_timeout(config['TIMEOUT_SECONDS'], start_time, app):
                    break
                
                sniff(
                    iface=network_interface,
                    filter=create_bpf_filter(
                        config['PROTOCOL'],
                        config['PORT'],
                        config['ADDITIONAL_BPF_FILTER']
                    ),
                    prn=lambda p: packet_callback(
                        p, 
                        config['FOUND_PACKETS_REQUIRED'], 
                        app
                    ),
                    store=0,
                    stop_filter=lambda x: not sniffing_active,
                    timeout=0.5
                )
        except Exception as e:
            app.status_label.config(text=f"Error: {str(e)}")
    
    threading.Thread(target=sniff_thread, daemon=True).start()

    def on_closing():
        global sniffing_active
        sniffing_active = False
        root.destroy()
        os._exit(0)  # Force exit all threads
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

except Exception as e:
    messagebox.showerror("Fatal Error", f"Application failed to start:\n{str(e)}")
    sys.exit(1)
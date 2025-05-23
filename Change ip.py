import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import re
import ipaddress

def get_adapters():
    result = subprocess.run(["netsh", "interface", "show", "interface"], capture_output=True, text=True)
    adapters = []
    for line in result.stdout.splitlines():
        match = re.search(r'^\s*Enabled\s+(?:Connected|Disconnected)\s+\S+\s+(.*)', line)
        if match:
            adapters.append(match.group(1).strip())
    return adapters

def get_current_ip(adapter_name):
    try:
        result = subprocess.run(
            ["netsh", "interface", "ip", "show", "address", f"name={adapter_name}"],
            capture_output=True, text=True
        )
        ip = re.search(r"IP Address:\s+([\d.]+)", result.stdout)
        mask = re.search(r"Subnet Prefix:\s+[\d.]+/(\d+)", result.stdout)
        gateway = re.search(r"Default Gateway:\s+([\d.]+)", result.stdout)

        if ip and mask:
            ip_entry.delete(0, tk.END)
            ip_entry.insert(0, ip.group(1))

            subnet_bits = int(mask.group(1))
            mask_str = str(ipaddress.IPv4Network(f'0.0.0.0/{subnet_bits}').netmask)
            mask_entry.delete(0, tk.END)
            mask_entry.insert(0, mask_str)

        if gateway:
            gateway_entry.delete(0, tk.END)
            gateway_entry.insert(0, gateway.group(1))
    except Exception as e:
        print("IP fetch failed:", e)

def on_adapter_selected(event):
    adapter = adapter_combo.get()
    get_current_ip(adapter)

def set_static_ip():
    adapter = adapter_combo.get()
    ip = ip_entry.get()
    mask = mask_entry.get()
    gateway = gateway_entry.get()

    try:
        subprocess.run([
            "netsh", "interface", "ip", "set", "address",
            f"name={adapter}", "static", ip, mask, gateway
        ], check=True)
        messagebox.showinfo("Success", f"IP set to {ip}")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to set IP:\n{e}")

def set_dhcp():
    adapter = adapter_combo.get()
    try:
        subprocess.run([
            "netsh", "interface", "ip", "set", "address",
            f"name={adapter}", "dhcp"
        ], check=True)
        messagebox.showinfo("Success", "Reverted to DHCP")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to revert:\n{e}")

# ───────────────────────── GUI ───────────────────────── #
root = tk.Tk()
root.title("🛠️ Network IP Config Tool")
root.resizable(False, False)

frame = ttk.Frame(root, padding=20)
frame.grid()

ttk.Label(frame, text="Select Network Adapter", font=("Segoe UI", 10, "bold")).grid(column=0, row=0, sticky="W")
adapter_combo = ttk.Combobox(frame, values=get_adapters(), width=30)
adapter_combo.grid(column=0, row=1, columnspan=2, pady=5)
adapter_combo.bind("<<ComboboxSelected>>", on_adapter_selected)

fields = {
    "IP Address:": "ip_entry",
    "Subnet Mask:": "mask_entry",
    "Default Gateway:": "gateway_entry"
}

row = 2
for label, varname in fields.items():
    ttk.Label(frame, text=label).grid(column=0, row=row, sticky="W", pady=3)
    entry = ttk.Entry(frame, width=30)
    entry.grid(column=1, row=row, pady=3)
    globals()[varname] = entry
    row += 1

ttk.Button(frame, text="Set Static IP", command=set_static_ip).grid(column=0, row=row, pady=10, sticky="EW")
ttk.Button(frame, text="Set to DHCP", command=set_dhcp).grid(column=1, row=row, pady=10, sticky="EW")

# Pre-fill first adapter
if adapter_combo['values']:
    adapter_combo.current(0)
    get_current_ip(adapter_combo.get())

root.mainloop()

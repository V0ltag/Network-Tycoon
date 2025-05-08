import tkinter as tk
from tkinter import simpledialog, messagebox
import random

class NetworkTycoonGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Tycoon - GUI Edition")

        self.money = 1000
        self.turn = 1
        self.servers = {}
        self.server_ports = {}
        self.firewall_rules = []
        self.breach_history = []
        self.selected_server = None

        self.setup_ui()
        self.generate_servers()

    def setup_ui(self):
        self.header = tk.Label(self.root, text=f"Turn: {self.turn}    Money: ${self.money}", font=('Helvetica', 12, 'bold'))
        self.header.pack(pady=10)

        self.server_frame = tk.Frame(self.root)
        self.server_frame.pack()

        self.button_frame = tk.Frame(self.root)
        self.button_frame.pack(pady=10)

        tk.Button(self.button_frame, text="Scan", command=self.scan_server).pack(side=tk.LEFT, padx=5)
        tk.Button(self.button_frame, text="Firewall Rules", command=self.manage_firewall).pack(side=tk.LEFT, padx=5)
        tk.Button(self.button_frame, text="Next Turn", command=self.next_turn).pack(side=tk.LEFT, padx=5)

        self.status = tk.Text(self.root, height=12, width=60)
        self.status.pack(pady=10)

    def generate_servers(self):
        for widget in self.server_frame.winfo_children():
            widget.destroy()

        self.servers.clear()
        self.server_ports.clear()

        for i in range(3):
            hostname = f"srv{i}.local"
            ip = f"192.168.0.{i + 10}"
            self.servers[i] = {"hostname": hostname, "ip": ip}
            self.server_ports[i] = random.sample([22, 80, 443, 3306, 21, 8080], 3)

            btn = tk.Button(self.server_frame, text=f"{hostname}\n{ip}", width=20, height=3,
                            command=lambda i=i: self.select_server(i))
            btn.grid(row=0, column=i, padx=10, pady=5)

    def select_server(self, i):
        self.selected_server = i
        server = self.servers[i]
        self.log(f"Selected {server['hostname']} ({server['ip']})")

    def scan_server(self):
        if self.selected_server is None:
            messagebox.showinfo("Error", "No server selected.")
            return
        ports = self.server_ports[self.selected_server]
        server = self.servers[self.selected_server]
        self.log(f"nmap scan of {server['hostname']} ({server['ip']}):")
        for port in ports:
            self.log(f"Port {port} OPEN")

    def manage_firewall(self):
        window = tk.Toplevel(self.root)
        window.title("Firewall Rules")

        listbox = tk.Listbox(window, width=40)
        listbox.pack(pady=5)
        for rule in self.firewall_rules:
            listbox.insert(tk.END, rule)

        def add_rule():
            rule = simpledialog.askstring("Add Rule", "Enter rule (e.g., BLOCK PORT 22):")
            if rule and rule not in self.firewall_rules:
                self.firewall_rules.append(rule)
                listbox.insert(tk.END, rule)
                self.log(f"Rule added: {rule}")

        def remove_rule():
            selected = listbox.curselection()
            if selected:
                rule = listbox.get(selected[0])
                self.firewall_rules.remove(rule)
                listbox.delete(selected[0])
                self.log(f"Rule removed: {rule}")

        btn_frame = tk.Frame(window)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Add Rule", command=add_rule).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Remove Rule", command=remove_rule).pack(side=tk.LEFT, padx=5)

    def next_turn(self):
        self.turn += 1
        self.header.config(text=f"Turn: {self.turn}    Money: ${self.money}")
        self.simulate_attack()

    def simulate_attack(self):
        target_id = random.choice(list(self.servers.keys()))
        port = random.choice(self.server_ports[target_id])
        rule = f"BLOCK PORT {port}"

        server = self.servers[target_id]
        if rule in self.firewall_rules:
            self.log(f"Blocked attack on {server['hostname']}:{port}")
        else:
            self.money -= 100
            self.header.config(text=f"Turn: {self.turn}    Money: ${self.money}")
            breach_msg = f"Breach on {server['hostname']} ({server['ip']}) at port {port}! Lost $100."
            self.breach_history.append(breach_msg)
            self.log(breach_msg)

    def log(self, message):
        self.status.insert(tk.END, message + "\n")
        self.status.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkTycoonGUI(root)
    root.mainloop()

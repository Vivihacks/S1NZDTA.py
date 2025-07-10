import os
import sys
import time
import random

# Terminal colors
C = {
    "R": "\033[91m",
    "G": "\033[92m",
    "Y": "\033[93m",
    "B": "\033[94m",
    "M": "\033[95m",
    "C": "\033[96m",
    "W": "\033[97m",
    "RESET": "\033[0m"
}

contracts_active = []
contracts_completed = []
botnet = []
compromised_ips = []
stored_ips = []

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def slow_type(text, delay=0.03):
    for c in text:
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def fake_login():
    clear()
    slow_type(C["G"] + "=== S1NZCI-EYE BLACKBOX LOGIN ===" + C["RESET"], 0.05)
    username = input(C["Y"] + "Username: " + C["RESET"])
    password = input(C["Y"] + "Password: " + C["RESET"])
    slow_type(C["C"] + "Authenticating..." + C["RESET"], 0.04)
    time.sleep(2)
    slow_type(C["G"] + f"Welcome, Agent {username}. Access Granted." + C["RESET"])
    time.sleep(1)

def banner():
    clear()
    print(C["R"] + "═" * 60)
    print(C["Y"] + "           S1NZCI-EYE // BLACKBOX OPS TERMINAL")
    print(C["R"] + "═" * 60)
    print(C["C"] + "ACCESS LEVEL: REDSHADOW | STATUS: ACTIVE | USER: AGENT")
    print(C["RESET"] + "-" * 60)

def generate_random_ip():
    blocks = [
        "10",
        "172." + str(random.randint(16, 31)),
        "192.168"
    ]
    block = random.choice(blocks)
    return f"{block}.{random.randint(1,254)}.{random.randint(1,254)}"

def generate_contract():
    missions = [
        "Intercept rogue AI node at {}",
        "Extract data from secured server {}",
        "Deploy backdoor on firewall {}",
        "Hijack communications at node {}",
        "Disable security protocol at {}",
        "Perform reconnaissance on network {}",
        "Execute ransomware simulation on {}",
        "Trace malware origin at {}"
    ]
    ip = generate_random_ip()
    mission = random.choice(missions).format(ip)
    contract = {
        "id": len(contracts_active) + len(contracts_completed) + 1,
        "description": mission,
        "target_ip": ip,
        "status": "ACTIVE"
    }
    contracts_active.append(contract)
    slow_type(C["G"] + f"[NEW CONTRACT] {contract['description']}" + C["RESET"])

def list_contracts():
    print(C["C"] + "\n=== ACTIVE CONTRACTS ===" + C["RESET"])
    if not contracts_active:
        print(C["R"] + "No active contracts." + C["RESET"])
    else:
        for c in contracts_active:
            print(f"{c['id']}. {c['description']} [{c['status']}]")
    print(C["C"] + "\n=== COMPLETED CONTRACTS ===" + C["RESET"])
    if not contracts_completed:
        print(C["R"] + "No completed contracts." + C["RESET"])
    else:
        for c in contracts_completed:
            print(f"{c['id']}. {c['description']} [{c['status']}]")
    input("\nPress Enter to continue...")

def port_scanner():
    clear()
    slow_type(C["Y"] + "=== PORT SCANNER ===" + C["RESET"])
    ip = input(C["Y"] + "Enter target IP: " + C["RESET"])
    slow_type(C["C"] + f"Scanning ports on {ip}..." + C["RESET"])
    time.sleep(1.5)
    open_ports = random.sample([21,22,23,25,53,80,110,143,443,445,993,995,3306,8080], random.randint(3,7))
    for port in sorted(open_ports):
        slow_type(C["G"] + f"Port {port}: OPEN" + C["RESET"], 0.2)
    input("\nPress Enter to continue...")

def backdoor_injector():
    clear()
    slow_type(C["Y"] + "=== BACKDOOR INJECTOR ===" + C["RESET"])
    ip = input(C["Y"] + "Enter target IP to backdoor: " + C["RESET"])
    if ip in compromised_ips:
        slow_type(C["R"] + "Target already compromised." + C["RESET"])
    else:
        slow_type(C["C"] + f"Injecting backdoor into {ip}..." + C["RESET"])
        time.sleep(2)
        slow_type(C["G"] + f"Backdoor successfully installed on {ip}." + C["RESET"])
        compromised_ips.append(ip)
    input("\nPress Enter to continue...")

def reverse_shell():
    clear()
    slow_type(C["Y"] + "=== REVERSE SHELL ACCESS ===" + C["RESET"])
    if not compromised_ips:
        slow_type(C["R"] + "No compromised targets available." + C["RESET"])
        input("\nPress Enter to continue...")
        return
    print(C["C"] + "Compromised targets:" + C["RESET"])
    for i, ip in enumerate(compromised_ips, 1):
        print(f"{i}. {ip}")
    choice = input(C["Y"] + "Select target by number: " + C["RESET"])
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(compromised_ips):
        slow_type(C["R"] + "Invalid selection." + C["RESET"])
        input("\nPress Enter to continue...")
        return
    target = compromised_ips[int(choice)-1]
    slow_type(C["C"] + f"Connecting to {target} shell..." + C["RESET"])
    time.sleep(1.5)
    shell_simulator(target)

def shell_simulator(ip):
    clear()
    slow_type(C["G"] + f"Connected to {ip} - Reverse Shell" + C["RESET"])
    commands = {
        "help": "Show this help message",
        "ls": "List directory contents",
        "cat": "View file content (fake)",
        "exit": "Close shell session",
        "whoami": "Show current user",
        "pwd": "Print working directory"
    }
    cwd = "/root"
    files = ["secret.txt", "passwords.txt", "data.db", "notes.log"]
    while True:
        cmd = input(C["G"] + f"root@{ip}:{cwd}$ " + C["RESET"]).strip()
        if cmd == "help":
            print(C["Y"] + "Available commands:" + C["RESET"])
            for k,v in commands.items():
                print(f" {k} - {v}")
        elif cmd == "ls":
            print(C["C"] + " ".join(files) + C["RESET"])
        elif cmd.startswith("cat "):
            fname = cmd[4:].strip()
            if fname in files:
                slow_type(C["G"] + f"Displaying contents of {fname}..." + C["RESET"])
                time.sleep(1)
                slow_type(f"--- BEGIN {fname} ---\n{random.choice(['Top secret data.', 'Credentials stored here.', 'Access logs.', 'System config info.'])}\n--- END ---")
            else:
                slow_type(C["R"] + f"File {fname} not found." + C["RESET"])
        elif cmd == "whoami":
            slow_type("root")
        elif cmd == "pwd":
            slow_type(cwd)
        elif cmd == "exit":
            slow_type(C["Y"] + "Closing shell session..." + C["RESET"])
            time.sleep(1)
            break
        else:
            slow_type(C["R"] + f"Command not found: {cmd}" + C["RESET"])

def ransomware_lockdown():
    clear()
    slow_type(C["Y"] + "=== RANSOMWARE LOCKDOWN ===" + C["RESET"])
    ip = input(C["Y"] + "Enter target IP for ransomware: " + C["RESET"])
    slow_type(C["C"] + f"Connecting to {ip}..." + C["RESET"])
    time.sleep(1.5)
    slow_type(C["R"] + "WARNING! Files are being encrypted!" + C["RESET"])
    countdown = 10
    while countdown > 0:
        print(C["R"] + f"Time until full encryption: {countdown} seconds" + C["RESET"], end="\r")
        time.sleep(1)
        countdown -= 1
    print()
    slow_type(C["R"] + f"System {ip} encrypted! Ransom demanded: 50 BTC" + C["RESET"])
    input("\nPress Enter to continue...")

def ddos_simulator():
    clear()
    slow_type(C["Y"] + "=== DDOS ATTACK SIMULATOR ===" + C["RESET"])
    ip = input(C["Y"] + "Enter target IP for attack: " + C["RESET"])
    slow_type(C["C"] + f"Launching DDOS on {ip}..." + C["RESET"])
    for i in range(10, 0, -1):
        print(C["R"] + f"Attack intensity: {i * 1000} packets/sec" + C["RESET"], end="\r")
        time.sleep(0.5)
    print()
    slow_type(C["G"] + f"DDOS on {ip} completed. Target offline." + C["RESET"])
    input("\nPress Enter to continue...")

def botnet_manager():
    clear()
    slow_type(C["Y"] + "=== BOTNET CHANNEL ===" + C["RESET"])
    while True:
        print(C["C"] + f"Bots active: {len(botnet)}" + C["RESET"])
        print("Commands: addbot, removebot, listbots, broadcast, back")
        cmd = input(C["Y"] + "botnet> " + C["RESET"]).strip().lower()
        if cmd == "addbot":
            bot_ip = generate_random_ip()
            botnet.append(bot_ip)
            slow_type(C["G"] + f"Bot {bot_ip} added to network." + C["RESET"])
        elif cmd == "removebot":
            if botnet:
                removed = botnet.pop()
                slow_type(C["R"] + f"Bot {removed} removed from network." + C["RESET"])
            else:
                slow_type(C["R"] + "No bots to remove." + C["RESET"])
        elif cmd == "listbots":
            if botnet:
                for i, b in enumerate(botnet, 1):
                    print(f"{i}. {b}")
            else:
                print(C["R"] + "No bots in network." + C["RESET"])
        elif cmd == "broadcast":
            if not botnet:
                slow_type(C["R"] + "No bots to broadcast to." + C["RESET"])
            else:
                msg = input(C["Y"] + "Enter command to broadcast: " + C["RESET"])
                slow_type(C["G"] + f"Broadcasting '{msg}' to {len(botnet)} bots..." + C["RESET"])
                for b in botnet:
                    slow_type(f"  Bot {b}: Executed '{msg}'", 0.05)
        elif cmd == "back":
            break
        else:
            slow_type(C["R"] + "Unknown command." + C["RESET"])

def file_stealer():
    clear()
    slow_type(C["Y"] + "=== FILE STEALER ===" + C["RESET"])
    ip = input(C["Y"] + "Enter target IP to steal files from: " + C["RESET"])
    slow_type(C["C"] + f"Accessing files on {ip}..." + C["RESET"])
    time.sleep(1.5)
    files = ["credentials.txt", "config.sys", "db_backup.sql", "notes.log", "admin_passwords.txt"]
    for f in files:
        slow_type(C["G"] + f"Downloaded {f}" + C["RESET"], 0.3)
    input("\nPress Enter to continue...")

def geo_trace():
    clear()
    slow_type(C["Y"] + "=== GEO-TRACE ===" + C["RESET"])
    ip = input(C["Y"] + "Enter IP to trace: " + C["RESET"])
    time.sleep(1)
    countries = ["USA", "Russia", "China", "Germany", "Brazil", "Canada", "India", "France"]
    cities = ["New York", "Moscow", "Beijing", "Berlin", "Rio de Janeiro", "Toronto", "Mumbai", "Paris"]
    country = random.choice(countries)
    city = random.choice(cities)
    slow_type(C["G"] + f"IP {ip} is located in {city}, {country}." + C["RESET"])
    input("\nPress Enter to continue...")

def ip_sniffer():
    clear()
    slow_type(C["Y"] + "=== IP SNIFFER ===" + C["RESET"])
    count = input(C["Y"] + "Number of IPs to sniff: " + C["RESET"])
    if not count.isdigit() or int(count) < 1:
        slow_type(C["R"] + "Invalid number." + C["RESET"])
        input("\nPress Enter to continue...")
        return
    count = int(count)
    slow_type(C["C"] + "Sniffing network traffic..." + C["RESET"])
    for _ in range(count):
        ip = generate_random_ip()
        slow_type(C["G"] + f"Captured IP: {ip}" + C["RESET"], 0.3)
    input("\nPress Enter to continue...")

def ip_storage_manager():
    clear()
    slow_type(C["Y"] + "=== IP STORAGE MANAGER ===" + C["RESET"])
    while True:
        print(C["C"] + f"Stored IPs: {len(stored_ips)}" + C["RESET"])
        print("Commands: addip, removeip, listips, back")
        cmd = input(C["Y"] + "storage> " + C["RESET"]).strip().lower()
        if cmd == "addip":
            ip = input(C["Y"] + "Enter IP to store: " + C["RESET"])
            if ip in stored_ips:
                slow_type(C["R"] + "IP already stored." + C["RESET"])
            else:
                stored_ips.append(ip)
                slow_type(C["G"] + f"IP {ip} added." + C["RESET"])
        elif cmd == "removeip":
            ip = input(C["Y"] + "Enter IP to remove: " + C["RESET"])
            if ip in stored_ips:
                stored_ips.remove(ip)
                slow_type(C["R"] + f"IP {ip} removed." + C["RESET"])
            else:
                slow_type(C["R"] + "IP not found." + C["RESET"])
        elif cmd == "listips":
            if stored_ips:
                for i, ip in enumerate(stored_ips, 1):
                    print(f"{i}. {ip}")
            else:
                print(C["R"] + "No stored IPs." + C["RESET"])
        elif cmd == "back":
            break
        else:
            slow_type(C["R"] + "Unknown command." + C["RESET"])

def hacker_shell():
    clear()
    slow_type(C["Y"] + "=== S1NZ TERMINAL SHELL ===" + C["RESET"])
    print("Type 'help' for commands, 'exit' to leave shell.")
    while True:
        cmd = input(C["G"] + "[sinz@eye]$ " + C["RESET"]).strip().lower()
        if cmd == "help":
            print(C["C"] + "Available commands:\n"
                  " trace   - Simulate a trace route\n"
                  " wipe    - Fake wipe target data\n"
                  " override- Fake override security\n"
                  " exit    - Exit shell\n"
                  " clear   - Clear terminal" + C["RESET"])
        elif cmd == "trace":
            slow_type(C["G"] + "Tracing route to target..." + C["RESET"])
            for i in range(1,6):
                time.sleep(0.5)
                slow_type(f"{i}\t{generate_random_ip()}")
        elif cmd == "wipe":
            slow_type(C["R"] + "Wiping target data... Done." + C["RESET"])
        elif cmd == "override":
            slow_type(C["Y"] + "Overriding security protocols... Success." + C["RESET"])
        elif cmd == "clear":
            clear()
        elif cmd == "exit":
            slow_type(C["Y"] + "Exiting shell..." + C["RESET"])
            time.sleep(1)
            break
        else:
            slow_type(C["R"] + f"Command not found: {cmd}" + C["RESET"])

def main_menu():
    while True:
        banner()
        print(C["B"] + "[1] Generate Contract")
        print("[2] List Contracts")
        print("[3] Port Scanner")
        print("[4] Backdoor Injector")
        print("[5] Reverse Shell")
        print("[6] Ransomware Lockdown")
        print("[7] DDOS Simulator")
        print("[8] Botnet Manager")
        print("[9] File Stealer")
        print("[10] Geo-Trace")
        print("[11] IP Sniffer")
        print("[12] IP Storage Manager")
        print("[13] Hacker Shell")
        print("[14] Exit" + C["RESET"])

        choice = input(C["Y"] + "\nSelect option: " + C["RESET"]).strip()
        if choice == "1":
            generate_contract()
            time.sleep(2)
        elif choice == "2":
            clear()
            list_contracts()
        elif choice == "3":
            port_scanner()
        elif choice == "4":
            backdoor_injector()
        elif choice == "5":
            reverse_shell()
        elif choice == "6":
            ransomware_lockdown()
        elif choice == "7":
            ddos_simulator()
        elif choice == "8":
            botnet_manager()
        elif choice == "9":
            file_stealer()
        elif choice == "10":
            geo_trace()
        elif choice == "11":
            ip_sniffer()
        elif choice == "12":
            ip_storage_manager()
        elif choice == "13":
            hacker_shellelif choice == "13":
            hacker_shell()
        elif choice == "14":
            slow_type(C["Y"] + "Exiting S1NZCI-EYE... Stay sharp, Agent." + C["RESET"])
            time.sleep(1)
            clear()
            sys.exit()
        else:
            slow_type(C["R"] + "Invalid option. Try again." + C["RESET"])
            time.sleep(1)

if __name__ == "__main__":
    fake_login()
    main_menu()

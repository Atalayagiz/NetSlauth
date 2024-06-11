import psutil
import socket
from datetime import datetime
import time
import os
import requests
from dotenv import load_dotenv

API_KEY = "Your API Key"
TXT_FILE = 'connections.txt'
VT_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'

# PID'lere karşılık gelen işlem adlarını saklamak için bir sözlük oluştur
pid_to_name = {}

# İşlem adlarını ve PID'leri alarak sözlüğe ekleyen bir fonksiyon
def update_pid_to_name():
    for proc in psutil.process_iter(['pid', 'name']):
        pid_to_name[proc.pid] = proc.name()

# Bağlantılarla ilişkilendirilmiş işlem adlarını elde eden bir fonksiyon
def get_process_name_for_connection(connection_info):
    pid = get_pid_for_connection(connection_info)
    if pid in pid_to_name:
        return pid_to_name[pid]
    return None

# PID değerini döndüren bir fonksiyon
def get_pid_for_connection(connection_info):
    connections = psutil.net_connections(kind='inet')
    for conn in connections:
        if conn.raddr and conn.raddr.ip == connection_info[0] and conn.raddr.port == connection_info[1]:
            return conn.pid
    return None

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_valid_dns(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False

def is_local_ip(ip):
    return ip.startswith("127.") or ip == "localhost"

def resolve_ip(ip_address):
    if is_valid_ip(ip_address):
        return ip_address
    elif is_valid_dns(ip_address):
        return socket.gethostbyname(ip_address)
    else:
        return None

def initialize_txt_file():
    if os.path.exists(TXT_FILE):
        os.remove(TXT_FILE)

    with open(TXT_FILE, 'w') as file:
        file.write("Timestamp | IP:Port | Application | Virustotal\n")

def load_previous_connections():
    if not os.path.exists(TXT_FILE):
        return set()
    
    with open(TXT_FILE, 'r') as file:
        file.readline()
        previous_connections = set()
        for line in file:
            parts = line.strip().split(' | ')
            ip_port = parts[1].split(':')
            previous_connections.add((ip_port[0], int(ip_port[1])))
        return previous_connections

def save_connection_to_txt(connection_info, vt_result, process_name):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ip, port = connection_info
    with open(TXT_FILE, 'a') as file:
        file.write(f"{timestamp} | {ip}:{port} | Application: {process_name} | Virustotal: {vt_result}\n")

def list_connections(previous_connections):
    connections = psutil.net_connections(kind='inet')
    current_connections = set()

    for conn in connections:
        if conn.raddr:
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            resolved_ip = resolve_ip(remote_ip)
            if resolved_ip and not is_local_ip(resolved_ip):
                connection_info = (resolved_ip, remote_port)
                current_connections.add(connection_info)

    new_connections = current_connections - previous_connections
    for connection_info in new_connections:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"{timestamp} | {connection_info[0]}:{connection_info[1]}")
        vt_result = check_virustotal(connection_info[0])
        process_name = get_process_name_for_connection(connection_info)
        if process_name:
            print(f"Application: {process_name}")
            save_connection_to_txt(connection_info, vt_result, process_name)
        else:
            print("Application: Null")
            save_connection_to_txt(connection_info, vt_result, "Null")
        print(f"Virustotal: {vt_result}\n")

    return current_connections



def check_virustotal(ip):
    headers = {
        'x-apikey': API_KEY
    }
    url = f"{VT_URL}{ip}"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        malicious_votes = data['data']['attributes']['last_analysis_stats']['malicious']
        if malicious_votes > 0:
            result = "Malicious"
        else:
            result = "Harmless"
        return result
    else:
        return "Error"

if __name__ == "__main__":
    initialize_txt_file()
    update_pid_to_name()  # İlk PID ve işlem adlarını yükle
    previous_connections = load_previous_connections()
    try:
        while True:
            previous_connections = list_connections(previous_connections)
            time.sleep(5)
    except KeyboardInterrupt:
        print("Stopped")

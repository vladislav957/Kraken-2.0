import socket

def scan_ports(target, ports):
    print(f"Сканирование {target}...")
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target, port))
        if result == 0:
            print(f"Порт {port} открыт")
        s.close()

# Пример использования
target_ip = "172.0.0.1"  # Замени на нужный IP
ports_to_scan = range(1, 1025)  # Сканируем порты от 1 до 1024
scan_ports(target_ip, ports_to_scan)




class Node:
    
    def __init__(self, name):
      self.name = name
      self.is_protected = True
      self.is_controlled = False 

    def disable_protection(self):
        print(f"[!] Защита {self.name} отключена")
        self.is_protected = False

    def apply_access(self):
        if not self.is_protected:
            self.is_controlled = True
            print(f" [+] Узел {self.name} теперь под контролем.")
        else:
            print(f" [x] Доступ запрещен. Cначала отключи защиту.")

            # Пример использования
            nl = Node("Узел-Alpha")
            nl.disable_protection()
            nl.apply_access()

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
target_ip = "192.0.0.1" # Замени на нужный IP
ports_to_scan = range(1, 1025)  # Сканируем порты от 1 до 1024
scan_ports(target_ip, ports_to_scan)

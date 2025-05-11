#from scanner import scan_network as scan_local # type: ignore
#from internet_scanner import scan_external_host # type: ignore
#from exploit_core import attempt_kernel_access # type: ignore
#from brute_force import brute_force_root # type: ignore
#from logger import log_event # type: ignore
#from stealth import enable_stealth_mode # type: ignore
import os
import hashlib
import itertools
import string

def scan_targets():
    # Определяем, использовать ли локальную или внешнюю сеть
    network_type = input("Выберите сеть (1 - локальная, 2 - интернет): ")

    if network_type == "1":
        subnet = input("Введите диапазон локальной сети (например, 192.168.1.0/24): ")
        targets = scan_local(subnet)
    elif network_type == "2":
        ip = input("Введите IP или домен для сканирования: ")
        targets = scan_external_host(ip)
    else:
        print("Неверный выбор. Пожалуйста, выберите 1 или 2.")
        return []

    return targets

def main():
    print("[*] Запуск Kraken 2.0")
    enable_stealth_mode()

    targets = scan_targets()
    if not targets:
        print("Не найдено целей.")
        return

    for target in targets:
        log_event(f"Обнаружена цель: {target}")
        if attempt_kernel_access(target):
            log_event(f"Попытка проникновения к ядру {target} успешна")
            brute_force_root(target)
        else:
            log_event(f"Доступ к ядру {target} отклонён")

if os.name == "main":
    main()

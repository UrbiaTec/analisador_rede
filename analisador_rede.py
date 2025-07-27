import psutil
import requests
from tabulate import tabulate
from typing import List, Dict, Any

suspeitos: Dict[str, str] = {'CN': 'China', 'RU': 'Russia', 'KP': 'North Korea', 'IR': 'Iran'}
key_proc: List[str] = ['crypto', 'miner', 'rat', 'hacker', 'backdoor', 'meterpreter', 'shell']

resumo: List[List[Any]] = []

for conn in psutil.net_connections(kind='inet'):
    if conn.raddr:
        # Protege contra casos em que raddr não tem os atributos esperados
        ip = getattr(conn.raddr, 'ip', None)
        port = getattr(conn.raddr, 'port', None)
        if (
            isinstance(ip, str)
            and not ip.startswith('127.')
            and not ip.startswith('192.168.')
            and ip != '0.0.0.0'
        ):
            try:
                proc = psutil.Process(conn.pid)
                nome_proc = proc.name()
            except Exception:
                nome_proc = 'Desconhecido'
            ip_info: Dict[str, Any] = {}
            try:
                r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
                ip_info = r.json() if r.status_code == 200 else {}
            except Exception:
                ip_info = {}
            pais: str = str(ip_info.get('country', ''))
            org: str = str(ip_info.get('org', ''))
            alerta = ''
            if pais in suspeitos:
                alerta += f"CONEXÃO COM PAÍS SUSPEITO ({suspeitos[pais]})! "
            if any(word in nome_proc.lower() for word in key_proc):
                alerta += "NOME DE PROCESSO SUSPEITO! "
            if not org:
                alerta += "IP EXTERNO SEM ORG DEFINIDA! "
            laddr_ip = getattr(conn.laddr, 'ip', '')
            laddr_port = getattr(conn.laddr, 'port', '')
            resumo.append([
                conn.pid,
                nome_proc,
                f"{laddr_ip}:{laddr_port}",
                f"{ip}:{port}",
                conn.status,
                f"{pais} {org}",
                alerta
            ])

saida = tabulate(
    resumo,
    headers=["PID", "Processo", "Local", "Remoto", "Estado", "País/IP info", "ALERTA"]
)

with open("log_rede.txt", "w", encoding="utf-8") as f:
    f.write(saida)
    if all(not linha[-1] for linha in resumo):
        f.write("\n\nNENHUMA CONEXÃO SUSPEITA DETECTADA!\n")
    else:
        f.write("\n\nCONEXÕES COM ALERTA IDENTIFICADO! VERIFIQUE LINHAS MARCADAS NA COLUNA 'ALERTA'.\n")

print("Relatório salvo em log_rede.txt!")
exit()
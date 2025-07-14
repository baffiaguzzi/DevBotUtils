import asyncio
import subprocess
import socket
import re
import csv
from telegram import Update
from telegram.ext import ContextTypes
from .log_utils import append_log_entry

try:
    from mac_vendor_lookup import MacLookup
except ImportError:
    MacLookup = None 


def get_local_subnet():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        subnet_parts = local_ip.split('.')[:-1]
        return '.'.join(subnet_parts) + '.0/24'
    except Exception:
        return None


def run_nmap_ping(subnet: str) -> subprocess.CompletedProcess:
    command = ["nmap", "-sn", subnet]
    result = subprocess.run(command, capture_output=True, text=True)
    return result


def get_arp_table():
    res = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    arp_entries = {}
    for line in res.stdout.splitlines():
        m = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17}|[0-9a-fA-F:-]{14})', line)
        if m:
            ip = m.group(1)
            mac = m.group(2).replace('-', ':').lower()
            arp_entries[ip] = mac
    return arp_entries


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/D"


def save_txt(devices, filename="scan_results.txt"):
    with open(filename, "w") as f:
        for d in devices:
            f.write(f"Hostname: {d['hostname']}\tIP: {d['ip']}\tMAC: {d['mac']}\tVendor: {d['vendor']}\n")


def save_csv(devices, filename="scan_results.csv"):
    with open(filename, "w", newline="") as csvfile:
        fieldnames = ["Hostname", "IP", "MAC", "Vendor"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for d in devices:
            writer.writerow({
                "Hostname": d["hostname"],
                "IP": d["ip"],
                "MAC": d["mac"],
                "Vendor": d["vendor"]
            })


async def scan_wifi_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"Comando /wifi lanciato")
    user = update.effective_user
    subnet = get_local_subnet() or "192.168.1.0/24"

    append_log_entry(
        "wifi",
        user.id,
        user.username or "",
        f"subnet={subnet}",
        "Avvio scansione rete locale"
    )

    await update.effective_message.reply_text(f"Avvio scansione rete locale {subnet}... Attendi...")
    loop = asyncio.get_running_loop()

    try:
        nmap_result = await loop.run_in_executor(None, run_nmap_ping, subnet)

        if nmap_result.stderr:
            error_msg = f"Errore durante la scansione nmap:\n{nmap_result.stderr}"
            await update.effective_message.reply_text(error_msg)
            append_log_entry(
                "wifi",
                user.id,
                user.username or "",
                f"subnet={subnet}",
                f"Errore nmap: {nmap_result.stderr}"
            )
            return

        matches = re.findall(
            r'Nmap scan report for (.+?) \((\d+\.\d+\.\d+\.\d+)\)|Nmap scan report for (\d+\.\d+\.\d+\.\d+)',
            nmap_result.stdout
        )
        devices = []
        for m in matches:
            if m[1]:
                hostname = m[0]
                ip = m[1]
            else: 
                hostname = "N/D"
                ip = m[2]
            if hostname == "N/D":
                hostname = resolve_hostname(ip)
            devices.append({"hostname": hostname, "ip": ip})

        if not devices:
            msg = "❌ Nessun dispositivo trovato nella rete!"
            await update.effective_message.reply_text(msg)
            append_log_entry(
                "wifi",
                user.id,
                user.username or "",
                f"subnet={subnet}",
                "Nessun dispositivo trovato"
            )
            return

        await update.effective_message.reply_text(f"Trovati {len(devices)} dispositivi attivi. Recupero MAC e vendor...")
        append_log_entry(
            "wifi",
            user.id,
            user.username or "",
            f"subnet={subnet}, dispositivi={len(devices)}",
            "Recupero MAC e vendor"
        )

        arp_table = get_arp_table()
        mac_lookup = None
        if MacLookup:
            mac_lookup = MacLookup()
            try:
                mac_lookup.update_vendors()
            except Exception:
                pass

        for idx, device in enumerate(devices, start=1):
            ip = device["ip"]
            mac = arp_table.get(ip, "N/D")
            vendor = "N/D"
            if mac != "N/D" and mac_lookup:
                try:
                    vendor = mac_lookup.lookup(mac)
                except Exception:
                    vendor = "N/D"
            device["mac"] = mac
            device["vendor"] = vendor
            msg = (
                f"[{idx}/{len(devices)}]\n"
                f"Hostname: {device['hostname']}\n"
                f"IP: {ip}\n"
                f"MAC: {mac}\n"
                f"Vendor: {vendor}"
            )
            await update.effective_message.reply_text(msg)

        save_txt(devices)
        save_csv(devices)

        await update.effective_message.reply_text("Scansione completata! Risultati salvati in scan_results.txt e scan_results.csv.")
        append_log_entry(
            "wifi",
            user.id,
            user.username or "",
            f"subnet={subnet}, dispositivi={len(devices)}",
            "Scansione completata con successo"
        )

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        error_text = f"❌ Errore durante la scansione:\n{str(e)}!\n\nTraceback:\n{tb}"
        await update.effective_message.reply_text(error_text)
        append_log_entry(
            "wifi",
            user.id,
            user.username or "",
            f"subnet={subnet}",
            f"Errore eccezione: {str(e)}"
        )
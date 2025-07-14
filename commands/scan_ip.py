import asyncio
from telegram import Update
from telegram.ext import ContextTypes
import nmap
from .log_utils import append_log_entry


def scan_network_sync(target, options=""):
    nm = nmap.PortScanner()
    scan_args = f"{target} {options}".strip()
    nm.scan(arguments=scan_args)
    return nm


async def scan_ip_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"Comando /ip lanciato")
    user = update.effective_user

    if not context.args:
        await update.effective_message.reply_text(
            "Inserisci un indirizzo IP o subnet da scansionare.\nEsempio:\n"
            "/ip 192.168.1.0/24 -sS -p 80,443 --script vuln"
        )
        return

    target = context.args[0]
    options = " ".join(context.args[1:]) if len(context.args) > 1 else ""

    append_log_entry(
        "ip",
        user.id,
        user.username or "",
        f"target={target}, options={options}",
        "Avvio scansione nmap"
    )

    await update.effective_message.reply_text(
        f"Avvio scansione nmap su {target} con opzioni: {options} ... Attendi..."
    )

    loop = asyncio.get_running_loop()
    try:
        nm = await loop.run_in_executor(None, scan_network_sync, target, options)
    except Exception as e:
        error_msg = f"❌ Errore durante la scansione: {e}!"
        await update.effective_message.reply_text(error_msg)
        append_log_entry(
            "ip",
            user.id,
            user.username or "",
            f"target={target}, options={options}",
            f"Errore scansione: {str(e)}"
        )
        return

    if target not in nm.all_hosts():
        msg = f"❌ Nessun host trovato per {target}!"
        await update.effective_message.reply_text(msg)
        append_log_entry(
            "ip",
            user.id,
            user.username or "",
            f"target={target}, options={options}",
            "Nessun host trovato"
        )
        return

    result = f"Risultati scansione per {target}:\n\n"
    for host in nm.all_hosts():
        state = nm[host].state()
        result += f"Host: {host} - Stato: {state}\n"
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            if len(ports) == 0:
                continue
            result += f"Porte ({proto}):\n"
            for port in sorted(ports):
                port_data = nm[host][proto][port]
                state = port_data['state']
                service = port_data.get('name', '')
                version = port_data.get('version', '')
                extra_info = f" ({version})" if version else ""
                result += f"- {port}/{proto}: {state} - {service}{extra_info}\n"
            for port in sorted(ports):
                port_data = nm[host][proto][port]
                if 'script' in port_data:
                    for script_name, output in port_data['script'].items():
                        result += f"  Script {script_name}: {output}\n"
        result += "\n"

    if len(result) > 3500:
        result = result[:3500] + "\n...[Output troncato]"

    await update.effective_message.reply_text(result)

    append_log_entry(
        "ip",
        user.id,
        user.username or "",
        f"target={target}, options={options}",
        f"Scansione completata, host trovati: {len(nm.all_hosts())}"
    )
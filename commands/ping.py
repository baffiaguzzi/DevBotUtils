import aiohttp
import aioping
import socket
import asyncio
import json
import os
import re
from datetime import datetime
from urllib.parse import urlparse
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from telegram.ext import MessageHandler, filters
from telegram.constants import ParseMode
from .log_utils import append_log_entry


async def check_https_port(host: str, port: int = 443, timeout: int = 3) -> bool:
    try:
        loop = asyncio.get_event_loop()
        fut = loop.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        infos = await fut
        
        for family, type, proto, canonname, sockaddr in infos:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(sockaddr[0], port), timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                return True
            except Exception:
                continue
        return False
    
    except Exception:
        return False


async def ping_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"Comando /ping lanciato")
    chat = update.effective_chat
    user = update.effective_user 
    print("→ Comando /ping ricevuto")
    
    await chat.send_message("→ Comando /ping ricevuto")
    if not context.args:
        print("→ Nessun argomento fornito")
        await chat.send_message("⚠️ Usa: /ping <host o IP>")
        return
    
    host = context.args[0]
    print(f"→ Ping a {host}")
    await chat.send_message(f"⏳ Eseguo ping a: {host}")
    log_result = f"Ping a: {host}\n"
    
    try:
        resolved_ip = socket.gethostbyname(host)
        print(f"→ IP risolto: {resolved_ip}")
        await chat.send_message(f"📍 IP risolto: {resolved_ip}")
        log_result += f"IP risolto: {resolved_ip}\n"
        
    except socket.gaierror:
        print("→ Errore risoluzione host")
        error_msg = f"❌ Dominio non valido o non risolvibile: {host}!"
        await chat.send_message(error_msg)
        log_result += error_msg + "\n"
        append_log_entry("ping", user.id, user.username or "", host, log_result)
        return
    
    try:
        delay = await aioping.ping(resolved_ip, timeout=2)
        delay_ms = delay * 1000
        print(f"→ Ping riuscito: {delay_ms:.2f} ms")
        success_msg = f"✅ Ping a {host} ({resolved_ip}) riuscito!\nTempo: {delay_ms:.2f} ms"
        await chat.send_message(success_msg)
        log_result += success_msg + "\n"
        
    except NotImplementedError:
        print("→ aioping non supportato, provo fallback TCP...")
        is_up = await check_https_port(resolved_ip)
        
        if is_up:
            fallback_msg = f"⚠️ ICMP non supportato, ma {host} ({resolved_ip}) risponde sulla porta 443 (HTTPS)."
            await chat.send_message(fallback_msg)
        else:
            fallback_msg = f"❌ ICMP non supportato, e nessuna risposta sulla porta 443 da {host} ({resolved_ip})."
            await chat.send_message(fallback_msg)
        log_result += fallback_msg + "\n"
        
    except TimeoutError:
        print("→ Timeout ping")
        timeout_msg = f"⚠️ Ping a {host} ({resolved_ip}) fallito (timeout)."
        
        await chat.send_message(timeout_msg)
        await chat.send_message("🔁 Verifico se la porta 443 (HTTPS) è raggiungibile...")
        is_open = await check_https_port(host)
        
        if is_open:
            port_msg = "✅ Porta 443 (HTTPS) **aperta**. Il server è raggiungibile via HTTPS."
        else:
            port_msg = "❌ Porta 443 **non raggiungibile**. Il server potrebbe essere offline o bloccato."
        await chat.send_message(port_msg)
        log_result += timeout_msg + "\n" + port_msg + "\n"
        
    except Exception as e:
        error_message = str(e) if str(e) else repr(e)
        print(f"→ Errore generico ping: {error_message}")
        error_msg = f"❌ Errore durante il ping a {host}!\nDettagli: {error_message}"
        await chat.send_message(error_msg)
        log_result += error_msg + "\n"
        
    append_log_entry("ping", user.id, user.username or "", host, log_result)

import aiohttp
import asyncio
import ssl
import socket
import time
from datetime import datetime
from telegram import Update
from telegram.ext import ContextTypes


def estrai_dominio(testo):
    import re
    match = re.search(r'https?://([\w.-]+)', testo)
    if match:
        return match.group(1).replace("www.", "")
    return testo 


async def check_ssl_cert(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                now = datetime.utcnow()
                valid = expire_date > now
                giorni_rimanenti = (expire_date - now).days
                return valid, giorni_rimanenti
    except Exception as e:
        return False, str(e)


async def analisi_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    
    if not context.args:
        await chat.send_message("⚠️ Usa: /analisi <url o IP>")
        return
    target = context.args[0]
    dominio = estrai_dominio(target)
    url = target
    
    if not (target.startswith("http://") or target.startswith("https://")):
        url = f"https://{target}"
        
    async with aiohttp.ClientSession() as session:
        start = time.time()
        try:
            async with session.get(url, timeout=10) as resp:
                end = time.time()
                status = resp.status
                headers = resp.headers
                text = await resp.text()
                ssl_check_result = "Non eseguito (non HTTPS)"
                
                if url.startswith("https://"):
                    valid_cert, ssl_info = await check_ssl_cert(dominio)
                    if valid_cert:
                        ssl_check_result = f"Certificato valido, scade tra {ssl_info} giorni"
                    else:
                        ssl_check_result = f"Problema certificato: {ssl_info}"
                        
                security_headers = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]
                missing_headers = [h for h in security_headers if h not in headers]
                error_keywords = ["error", "not found", "exception", "denied", "forbidden", "internal server error"]
                found_errors = [kw for kw in error_keywords if kw.lower() in text.lower()]
                msg = f"🔍 Analisi sito: {url}\n"
                msg += f"⏱ Tempo risposta: {round((end - start)*1000)} ms\n"
                msg += f"📶 Stato HTTP: {status}\n"
                msg += f"🔒 SSL: {ssl_check_result}\n"
                
                if missing_headers:
                    msg += f"⚠️ Headers di sicurezza mancanti: {', '.join(missing_headers)}\n"
                else:
                    msg += "✅ Tutti gli header di sicurezza principali presenti.\n"
                if found_errors:
                    msg += f"⚠️ Parole chiave di errore trovate nella pagina: {', '.join(found_errors)}\n"
                else:
                    msg += "✅ Nessuna parola chiave di errore trovata nel contenuto.\n"
                await chat.send_message(msg)
                
        except asyncio.TimeoutError:
            await chat.send_message(f"❌ Timeout: il sito {url} non risponde!")
            
        except aiohttp.ClientError as e:
            await chat.send_message(f"❌ Errore di connessione: {str(e)}!")
            
        except Exception as e:
            await chat.send_message(f"❌ Errore imprevisto: {str(e)}!")

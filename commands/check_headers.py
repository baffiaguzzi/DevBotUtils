import aiohttp
import re
from telegram import Update
from telegram.ext import ContextTypes
from .log_utils import append_log_entry


SECURITY_HEADERS = {
    "content-security-policy": "Protegge contro XSS e injection limitando risorse caricate",
    "strict-transport-security": "Forza HTTPS per comunicazioni sicure",
    "x-content-type-options": "Previene MIME sniffing (di solito 'nosniff')",
    "x-frame-options": "Previene clickjacking (es. 'DENY' o 'SAMEORIGIN')",
    "referrer-policy": "Controlla quali info referer inviare",
    "permissions-policy": "Controlla permessi per funzionalità browser (es. geoloc, webcam)"
}


SENSITIVE_HEADERS = {
    "server": "Versione e software del server web esposto",
    "x-powered-by": "Tecnologia backend esposta",
    "x-aspnet-version": "Versione ASP.NET esposta",
    "x-aspnetmvc-version": "Versione ASP.NET MVC esposta"
}


SUGGESTIONS = {
    "content-security-policy": "Implementa una policy CSP restrittiva per prevenire XSS e injection.",
    "strict-transport-security": "Abilita HSTS per forzare HTTPS e prevenire downgrade attack.",
    "x-content-type-options": "Imposta 'nosniff' per evitare MIME sniffing dannosi.",
    "x-frame-options": "Usa 'DENY' o 'SAMEORIGIN' per prevenire clickjacking.",
    "referrer-policy": "Configura il referrer policy per ridurre perdita di privacy.",
    "permissions-policy": "Limita le permissioni browser alle sole necessarie per la tua app.",
    "server": "Nascondi o modifica header Server per non rivelare info sul backend.",
    "x-powered-by": "Disabilita o modifica header X-Powered-By per migliorare sicurezza.",
    "x-aspnet-version": "Evita di esporre versioni software nel header.",
    "x-aspnetmvc-version": "Evita di esporre versioni software nel header."
}


def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"https?://", url):
        url = "https://" + url
    return url


async def check_headers_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"Comando /headers lanciato")
    user = update.effective_user
    msg = update.effective_message
    
    if not context.args:
        await msg.reply_text(
            "❌ Devi specificare l'URL!\n"
            "Esempio:\n"
            "/headers https://example.com"
        )
        return
    
    url = normalize_url(context.args[0])
    await msg.reply_text(f"🔍 Verifico gli header HTTP di {url}...")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, allow_redirects=True) as resp:
                headers = resp.headers
                status = resp.status
        sensitive_found = {h: headers[h] for h in headers if h.lower() in SENSITIVE_HEADERS}
        security_report = {}
        missing_security = []
        
        for sh in SECURITY_HEADERS:
            if sh in headers:
                security_report[sh] = f"✅ Presente: {headers[sh]}"
            else:
                security_report[sh] = "❌ Mancante"
                missing_security.append(sh)

        msg_text = f"🔍 Risultato per {url}:\n"
        msg_text += f"📟 Status Code: {status}\n\n"
        
        if sensitive_found:
            msg_text += "⚠️ Header sensibili rilevati:\n"
            for h, v in sensitive_found.items():
                descr = SENSITIVE_HEADERS.get(h.lower(), "")
                msg_text += f" - {h}: {v} ({descr})\n"
            msg_text += "\n"
        msg_text += "🔒 Controllo header di sicurezza:\n"
        
        for h, status_text in security_report.items():
            descr = SECURITY_HEADERS[h]
            msg_text += f" - {h}: {status_text} ({descr})\n"
        msg_text += "\n💡 Suggerimenti:\n"
        
        for sh in missing_security:
            msg_text += f" - {SUGGESTIONS.get(sh, 'Nessun suggerimento disponibile')}\n"
        for sh in sensitive_found:
            msg_text += f" - {SUGGESTIONS.get(sh.lower(), 'Nessun suggerimento disponibile')}\n"
        await msg.reply_text(msg_text)
        
        append_log_entry(
            "headers",
            user.id,
            user.username or "",
            url,
            msg_text
        )
        
    except Exception as e:
        error_msg = f"❌ Errore durante la richiesta: {e}!"
        await msg.reply_text(error_msg)
        append_log_entry(
            "headers_error",
            user.id,
            user.username or "",
            url,
            error_msg
        )
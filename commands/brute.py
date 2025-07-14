import re
import requests
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode
from urllib.parse import urljoin, quote
from datetime import datetime
from .log_utils import append_log_entry


DEFAULT_PATHS = [
    '/', '/index.html', '/home', '/dashboard', '/admin', '/login', '/main',
    '/app', '/user', '/control', '/status', '/api', '/portal',
    '/assign-order', '/prepare-order', '/partial-orders', '/pm-orders', '/firmare', '/borderò',
    '/status', '/history', '/storico-parziali', '/agents', '/accounts', '/chat',
    '/products', '/quality', '/stats', '/settings'
]

FAKE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

def normalize_url(input_url: str) -> str:
    if not re.match(r'^https?://', input_url):
        return f"https://{input_url}"
    if input_url.startswith("http://"):
        return input_url.replace("http://", "https://", 1)
    return input_url


def chunk_output(lines, size=10):
    for i in range(0, len(lines), size):
        yield lines[i:i+size]


async def brute_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"Comando /brute lanciato")
    msg = update.effective_message
    args = context.args
    
    if update.callback_query:
        await update.callback_query.answer()
        await update.callback_query.edit_message_text(
            "📥 Usa il comando /brute seguito da un URL o IP per fare il brute force sui percorsi.\n\n"
            "Esempio:\n"
            "/brute example.com --full --headers --follow\n"
            "Opzioni:\n"
            " --full per scan completo\n"
            " --preview per vedere dimensioni contenuto\n"
            " --headers per mostrare headers HTTP\n"
            " --follow per seguire redirect\n"
            " --custom=/path1,/path2 per percorsi personalizzati",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    message = update.message
    if not message:
        return
    args = context.args
    
    if not args:
        await message.reply_text(
            "❌ Specifica un URL o IP valido!\n\n"
            "Uso: /brute <url> [--full] [--preview] [--headers] [--follow] [--custom=/path1,/path2]",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    url_base = normalize_url(args[0])
    flags = args[1:] if len(args) > 1 else []

    full = '--full' in flags
    preview = '--preview' in flags
    show_headers = '--headers' in flags
    follow_redirects = '--follow' in flags
    custom_paths = []
    
    for flag in flags:
        if flag.startswith('--custom='):
            raw = flag.split('=', 1)[1]
            custom_paths = [f"/{p.strip()}" for p in raw.split(',') if p.strip()]
    if custom_paths:
        paths = custom_paths
    elif full:
        paths = DEFAULT_PATHS + ['/config', '/setup', '/test', '/settings', '/phpmyadmin']
    else:
        paths = DEFAULT_PATHS
    await message.reply_text(
        f"🔍 Avvio scan su `{url_base}` con {len(paths)} percorsi...",
        parse_mode=ParseMode.MARKDOWN
    )
    results = []
    
    with requests.Session() as session:
        session.headers.update(FAKE_HEADERS)
        for path in paths:
            quoted_path = quote(path, safe='/')
            url = urljoin(url_base, quoted_path)
            try:
                resp = session.get(url, allow_redirects=follow_redirects, timeout=5)
                status = resp.status_code
                if status == 200:
                    content_info = f"({len(resp.text)}B)" if preview else ""
                    line = f"[✅ {status}] {url} {content_info}"
                elif status in (301, 302):
                    loc = resp.headers.get('Location', '')
                    line = f"[🔁 {status}] {url} ➝ {loc}"
                elif status == 403:
                    line = f"[🚫 {status}] {url}"
                else:
                    line = f"[{status}] {url}"
                results.append(line)
                if show_headers:
                    for h, v in resp.headers.items():
                        results.append(f"    ↳ {h}: {v}")
                append_log_entry({
                    "timestamp": datetime.now().isoformat(),
                    "command": "/brute",
                    "url": url,
                    "status": status,
                    "follow_redirects": follow_redirects,
                    "preview": preview,
                    "show_headers": show_headers,
                    "error": None
                })
                
            except requests.RequestException as e:
                error_line = f"[Error] {url} --> {e}"
                results.append(error_line)
                append_log_entry({
                    "timestamp": datetime.now().isoformat(),
                    "command": "/brute",
                    "url": url,
                    "status": None,
                    "follow_redirects": follow_redirects,
                    "preview": preview,
                    "show_headers": show_headers,
                    "error": str(e)
                })
                
    for chunk in chunk_output(results, 8):
        await message.reply_text("```\n" + "\n".join(chunk) + "\n```", parse_mode=ParseMode.MARKDOWN)
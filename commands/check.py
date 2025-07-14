from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import asyncio
from urllib.parse import urlparse
from telegram.constants import ParseMode
from .log_utils import append_log_entry


def format_size(kb):
    return f"{kb:.2f} KB"


def test_performance(url):
    try:
        start = time.time()
        response = requests.get(url)
        response.raise_for_status()
        total_time = time.time() - start
    except Exception as e:
        return f"❌ Errore nel caricamento: {e}!"
    
    soup = BeautifulSoup(response.text, "html.parser")
    html_size_kb = len(response.content) / 1024
    images = soup.find_all("img")
    scripts = soup.find_all("script")
    links = soup.find_all("link", rel="stylesheet")
    resources = []
    
    for tag in images + scripts + links:
        src = tag.get("src") if tag.name != "link" else tag.get("href")
        if src:
            full_url = urljoin(url, src)
            resources.append(full_url)
            
    unique_resources = set(resources)
    avg_resource_size_kb = 50 
    https_flag = "🔐 HTTPS" if url.lower().startswith("https") else "⚠️ HTTP"
    
    result = (
        f"⏱️ Tempo caricamento pagina: {total_time:.2f} sec\n"
        f"📄 Dimensione HTML: {format_size(html_size_kb)}\n"
        f"🖼️ Immagini: {len(images)}\n"
        f"📜 Script JS: {len(scripts)}\n"
        f"🎨 CSS: {len(links)}\n"
        f"🔗 Risorse esterne totali: {len(resources)} (uniche: {len(unique_resources)})\n"
        f"⚖️ Dimensione media stimata per risorsa: {format_size(avg_resource_size_kb)}\n"
        f"{https_flag}\n"
        f"🔎 Risorse caricate:\n"
    )
    
    for res in list(unique_resources)[:10]:
        result += f"• {res}\n"
    if len(unique_resources) > 10:
        result += f"... e altre {len(unique_resources) - 10} risorse\n"
    return result


def normalize_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url 
    return url


async def performance_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"Comando /performance lanciato")
    user = update.effective_user
    msg = update.effective_message
    
    if update.callback_query:
        await update.callback_query.answer()
        await update.callback_query.edit_message_text(
            "⚡ Usa il comando /performance seguito da un URL per testare la performance.\n\nEsempio:\n`/performance https://example.com`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    if msg is None:
        return
    if not context.args:
        await msg.reply_text(
            "⚡ Inserisci un URL da analizzare: `/performance <url>`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    raw_url = context.args[0]
    url = normalize_url(raw_url)
    result = await asyncio.to_thread(test_performance, url)
    
    await msg.reply_text(result)
    log_result = f"Performance test su URL: {url}\nRisultato:\n{result}"
    append_log_entry("performance", user.id, user.username or "", url, log_result)
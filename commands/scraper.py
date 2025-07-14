import os
import json
import zipfile
from telegram import Update
from telegram.constants import ChatAction
from telegram.ext import ContextTypes
from playwright.async_api import async_playwright
from urllib.parse import urlparse
from .log_utils import append_log_entry


OUTPUT_DIR = 'output'


def normalize_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    if not parsed.scheme:
        return 'http://' + raw_url
    return raw_url


async def scrape_website(url: str):
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless = False,      
            slow_mo = 100          
        )
        context = await browser.new_context(
            user_agent='Mozilla/5.0 (compatible; MonitorServerDevBot/1.0)',
            locale='en-US'
        )
        await context.add_init_script("""Object.defineProperty(navigator, 'webdriver', { get: () => undefined })""")
        page = await context.new_page()
        
        try:
            response = await page.goto(url, wait_until='load', timeout=60000)
            await page.wait_for_timeout(10000)  
            
        except Exception as e:
            await browser.close()
            raise Exception(f"Errore navigazione: {str(e)}")
        html = await page.content()
        
        with open(f'{OUTPUT_DIR}/page.html', 'w', encoding='utf-8') as f:
            f.write(html)
        headers = dict(response.headers) if response else {}
        
        with open(f'{OUTPUT_DIR}/headers.json', 'w') as f:
            json.dump(headers, f, indent=2)
        cookies = await context.cookies()
        
        with open(f'{OUTPUT_DIR}/cookies.json', 'w') as f:
            json.dump(cookies, f, indent=2)
        await page.screenshot(path=f'{OUTPUT_DIR}/screenshot.png')
        await browser.close()
        
    with zipfile.ZipFile(f'{OUTPUT_DIR}/scrape.zip', 'w') as zf:
        zf.write(f'{OUTPUT_DIR}/page.html', 'page.html')
        zf.write(f'{OUTPUT_DIR}/headers.json', 'headers.json')
        zf.write(f'{OUTPUT_DIR}/cookies.json', 'cookies.json')
        zf.write(f'{OUTPUT_DIR}/screenshot.png', 'screenshot.png')


async def scraper_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"Comando /scraper lanciato")
    msg = update.effective_message
    user = update.effective_user

    if not context.args:
        await msg.reply_text("❗ Usa il comando così:\n`/scraper http://esempio.com`", parse_mode='Markdown')
        append_log_entry(
            "scraper",
            user.id,
            user.username or "",
            "url=N/D",
            "Argomento mancante nel comando"
        )
        return

    url = normalize_url(context.args[0])

    await msg.reply_text(f"🚀 Avvio scraping per: {url}")
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)

    append_log_entry(
        "scraper",
        user.id,
        user.username or "",
        f"url={url}",
        "Avvio scraping"
    )

    try:
        await scrape_website(url)

        await msg.reply_text("✅ Scraping completato. Invio file...")

        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=open(f'{OUTPUT_DIR}/page.html', 'rb'),
            filename="page.html"
        )
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=open(f'{OUTPUT_DIR}/headers.json', 'rb'),
            filename="headers.json"
        )
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=open(f'{OUTPUT_DIR}/cookies.json', 'rb'),
            filename="cookies.json"
        )
        await context.bot.send_photo(
            chat_id=update.effective_chat.id,
            photo=open(f'{OUTPUT_DIR}/screenshot.png', 'rb')
        )
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=open(f'{OUTPUT_DIR}/scrape.zip', 'rb'),
            filename="scrape.zip"
        )

        append_log_entry(
            "scraper",
            user.id,
            user.username or "",
            f"url={url}",
            "Scraping completato e file inviati"
        )

    except Exception as e:
        error_msg = f"❌ Errore durante scraping: {str(e)}!"
        await msg.reply_text(error_msg)
        append_log_entry(
            "scraper",
            user.id,
            user.username or "",
            f"url={url}",
            f"Errore: {str(e)}"
        )

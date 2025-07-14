import aiohttp
import aioping
import socket
import asyncio
import nest_asyncio
import json
import os
import re
from datetime import datetime
from urllib.parse import urlparse
from telegram import Update, BotCommand, InputFile
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from telegram.ext import MessageHandler, filters
from telegram.constants import ParseMode
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters
from commands import (
    analisi, api, log, security, seo, ssl, inject, start, jwt, scraper, brute, check_api, check_headers, pma_brute, scan_ip, scan_wifi, help, ping, check, unknown, vulnerability, deep, deep_commands
)
from utils import set_commands
import config
from config import is_authorized
from commands.vulnerability import start_scheduler
from commands.deep_commands import get_deep_handlers, deep_callback
from telegram.ext import CallbackQueryHandler
from dotenv import load_dotenv
import sys

# Correzione necessaria per Playwright su Windows
if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())


load_dotenv()
ALLOWED_USERS = list(map(int, filter(None, os.getenv("ALLOWED_USERS", "").split(","))))


async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    
    user_id = query.from_user.id

    if not is_authorized(user_id):
        await query.answer("❌ Non sei autorizzato ad accedere a questo bot!", show_alert=True)
        return
    
    await query.answer()

    cmd = query.data
    if cmd == "ping":
        await ping.ping_command(update, context)    
    elif cmd == "analisi":
        await analisi.analisi_check(update, context)    
    elif cmd == "headers":
        await check_headers.check_headers_command(update, context)
    elif cmd == "ssl":
        await ssl.ssl_command(update, context)
    elif cmd == "performance":
        await check.performance_handler(update, context)
    elif cmd == "seo":
        await seo.seo_command(update, context)
    elif cmd == "vulnerability":
        await vulnerability.vulnerability_command(update, context)        
    elif cmd == "security":
        await security.security_command(update, context)    
    elif cmd == "analisi":
        await analisi.analisi_check(update, context)
    elif cmd == "api_easy":
        await api.api_command(update, context)        
    elif cmd == "api_pro":
        await check_api.check_api_command(update, context)        
    elif cmd == "ip":
        await scan_ip.scan_ip_command(update, context)
    elif cmd == "wifi":
        await scan_wifi.scan_wifi_command(update, context)    
    elif cmd == "scraper":
        await scraper.scraper_command(update, context)
    elif cmd == "jwt":
        await jwt.jwt_command(update, context)        
    elif cmd == "pentest":
        await pma_brute.pma_brute(update, context)
    elif cmd == "brute":
        await brute.brute_command(update, context)        
    elif cmd == "inject":
        await inject.inject_command(update, context)
    elif cmd == "log":
        await log.log_command(update, context)
    else:
        await query.edit_message_text("Comando non riconosciuto.")


async def main():
    app = ApplicationBuilder().token(config.BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start.start))
    app.add_handler(CommandHandler("help", help.help_command))    
    app.add_handler(CommandHandler("ping", ping.ping_command))
    app.add_handler(CommandHandler("analisi", analisi.analisi_check))    
    app.add_handler(CommandHandler("headers", check_headers.check_headers_command))
    app.add_handler(CommandHandler("ssl", ssl.ssl_command))
    app.add_handler(CommandHandler("performance", check.performance_handler))    
    app.add_handler(CommandHandler("seo", seo.seo_command))    
    app.add_handler(CommandHandler("vulnerability", vulnerability.vulnerability_command))
    app.add_handler(CommandHandler("security", security.security_command))    
    app.add_handler(CommandHandler("api_easy", api.api_command))    
    app.add_handler(CommandHandler("api_pro", check_api.check_api_command))    
    app.add_handler(CommandHandler("ip", scan_ip.scan_ip_command))
    app.add_handler(CommandHandler("wifi", scan_wifi.scan_wifi_command))    
    app.add_handler(CommandHandler("scraper", scraper.scraper_command))
    app.add_handler(CommandHandler("jwt", jwt.jwt_command))    
    app.add_handler(CommandHandler("pentest", pma_brute.pma_brute))
    app.add_handler(CommandHandler("brute", brute.brute_command))    
    app.add_handler(CommandHandler("inject", inject.inject_command))
    app.add_handler(CommandHandler("log", log.log_command))

    app.add_handler(CallbackQueryHandler(menu_callback))

    chat_id = 6719207577  
    
    for handler in get_deep_handlers():
        app.add_handler(handler)

    app.add_handler(MessageHandler(filters.COMMAND, unknown.unknown))

    await set_commands(app)
    
    vulnerability.start_scheduler(app, chat_id)

    print("Bot avviato...")
    await app.run_polling()

if __name__ == "__main__":
    import asyncio
    import nest_asyncio
    nest_asyncio.apply()
    asyncio.get_event_loop().run_until_complete(main())

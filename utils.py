from functools import wraps
from telegram import Update
from telegram.ext import ContextTypes
from config import is_authorized

def require_auth():
    def decorator(func):
        @wraps(func)
        async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
            user_id = update.effective_user.id
            if not is_authorized(user_id):
                if update.message:
                    await update.message.reply_text("❌ Accesso non autorizzato!")
                elif update.callback_query:
                    await update.callback_query.answer("❌ Accesso non autorizzato!", show_alert=True)
                return
            return await func(update, context, *args, **kwargs)
        return wrapper
    return decorator


def estrai_dominio(url: str) -> str:
    import re
    pattern = r"https?://([^/]+)"
    match = re.match(pattern, url)
    return match.group(1) if match else ""


async def set_commands(app):
    from telegram import BotCommand
    commands = [
        BotCommand("start", "Avvia il bot"),
        BotCommand("help", "Mostra i comandi disponibili"),
        
        BotCommand("ping", "Test risposta dell'url"),
        BotCommand("analisi", "Analisi base dell'url"),
        
        BotCommand("header", "Test headers dell'url"),
        BotCommand("ssl", "Analisi SSL dell'url"),
        
        BotCommand("performance", "Test performance dell'url"),
        BotCommand("seo", "Analisi SEO dell'url"),
        
        BotCommand("vulnerability", "Testa possibili vulnerabilità dell'url"),
        BotCommand("security", "Testa la sicurezza dell'url"),
        
        BotCommand("api_easy", "Analizza l'endpoint dell'url"),
        BotCommand("api_pro", "Postman versione bot"),
        
        BotCommand("ip", "Scansione IP della rete"),
        BotCommand("wifi", "Nmap versione bot"),
        
        BotCommand("scraper", "Analizza la SEO del sito"),
        BotCommand("jwt", "Analizza il token"),
        
        BotCommand("pentest", "Pentesting"),
        BotCommand("brute", "Testa le porte del sito/ip"),       
        
        BotCommand("inject", "Testa possibili attacchi con Injection"),
        BotCommand("log", "Mostra il log della giornata")
    ]
    await app.bot.set_my_commands(commands)

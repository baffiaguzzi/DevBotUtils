from telegram import Update
from telegram.ext import ContextTypes


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "Ecco i comandi disponibili:\n"
        "/start - Avvia il bot\n"
        "/help - Mostra i comandi disponibili\n"        
        "/ping - Test risposta dell'url\n"
        "/analisi - Analisi base dell'url\n"
        "/header - Test headers dell'url\n"
        "/ssl - Analisi SSL dell'url\n"
        "/performance - Test performance dell'url\n"
        "/seo - Analisi SEO dell'url\n"
        "/vulnerability - Testa possibili vulnerabilità dell'url\n"
        "/security - Testa la sicurezza dell'url\n"
        "/api_easy - Analizza l'endpoint dell'url\n"
        "/api_pro - Postman versione bot\n"
        "/ip - Scansione IP della rete\n"
        "/wifi - Nmap versione bot\n"
        "/scraper - Analizza la SEO del sito\n"
        "/jwt - Analizza il token\n"
        "/pentest - Pentesting\n"
        "/brute - Testa le porte del sito/ip\n"
        "/inject - Testa possibili attacchi con Injection\n"
        "/log - Mostra il log della giornata\n"
    )
    await update.message.reply_text(help_text)

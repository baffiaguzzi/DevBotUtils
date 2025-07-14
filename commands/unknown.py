from telegram import Update
from telegram.ext import ContextTypes


async def unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message:
        await update.message.reply_text("❌ Comando non riconosciuto! Usa /help per la lista dei comandi.")
    elif update.callback_query:
        await update.callback_query.answer("❌ Comando non riconosciuto!")


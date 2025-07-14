import os
from telegram import Update
from telegram.ext import ContextTypes
from datetime import datetime
from .log_utils import _get_log_file_path 


async def log_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    log_path = _get_log_file_path()

    if not os.path.exists(log_path):
        if update.message:
            await update.message.reply_text("📭 Nessun log trovato per oggi.")
        elif update.callback_query:
            await update.callback_query.answer()
            await update.callback_query.message.reply_text("📭 Nessun log trovato per oggi.")
        else:
            print("📭 Nessun log trovato e nessun modo per rispondere.")
        return

    try:
        with open(log_path, "rb") as f:
            if update.message:
                await update.message.reply_document(document=f, filename=os.path.basename(log_path))
            elif update.callback_query:
                await update.callback_query.answer()
                await update.callback_query.message.reply_document(document=f, filename=os.path.basename(log_path))
            else:
                print(f"Invio log fallito: nessun messaggio o callback_query per inviare il documento")
        print(f"✅ Log inviato all'utente {user.username or user.id}")
        
    except Exception as e:
        print(f"❌ Errore nell'invio del log: {e}")
        if update.message:
            await update.message.reply_text(f"Errore nel recupero del log: {e}")
        elif update.callback_query:
            await update.callback_query.answer()
            await update.callback_query.message.reply_text(f"Errore nel recupero del log: {e}")



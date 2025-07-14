from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, CallbackQueryHandler
from config import is_authorized
from utils import require_auth


@require_auth()
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):   
    user_id = update.effective_user.id
    username = update.effective_user.username

    print(f"ID utente: {user_id} | Username: @{username}")
    
    keyboard = [
        [
            InlineKeyboardButton("🛰️ Ping", callback_data="ping"),
            InlineKeyboardButton("📊 Analisi", callback_data="analisi")
        ],
        [   
            InlineKeyboardButton("📄 Header", callback_data="headers"),
            InlineKeyboardButton("🛡️ SSL", callback_data="ssl")
        ],
        [   
            InlineKeyboardButton("⚡ Performance", callback_data="performance"),
            InlineKeyboardButton("🌐 SEO", callback_data="seo")
        ],
        [
            InlineKeyboardButton("🔍 Vulnerabilità", callback_data="vulnerability"),
            InlineKeyboardButton("🔐 Sicurezza", callback_data="security")
        ],
        [
            InlineKeyboardButton("🧪 API Tester easy", callback_data="api_easy"),
            InlineKeyboardButton("🚀 API Tester pro", callback_data="api_pro")            
        ],
        [   
            InlineKeyboardButton("📡 Scan IP", callback_data="ip"),
            InlineKeyboardButton("📶 Scan WiFi", callback_data="wifi")
        ],
        [
            InlineKeyboardButton("🤖 Scraper", callback_data="scraper"),
            InlineKeyboardButton("🪪 JWT", callback_data="jwt")
        ],
        [
            InlineKeyboardButton("🕵️ PMA Brute", callback_data="pentest"),
            InlineKeyboardButton("💣 Brute Ports", callback_data="brute")
        ],
        [InlineKeyboardButton("🧬 Inject", callback_data="inject")],
        [InlineKeyboardButton("📜 Log", callback_data="log")]
    ]

    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("Benvenuto! Scegli un'analisi da avviare:", reply_markup=reply_markup)

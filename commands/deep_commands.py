from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, CommandHandler, CallbackQueryHandler
from commands.deep import get_deep_info, vulnerability_insights


async def deep_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        keyboard = [
            [InlineKeyboardButton(v["title"], callback_data=key)]
            for key, v in vulnerability_insights.items()
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text(
            "Seleziona una vulnerabilità per ricevere dettagli e consigli:",
            reply_markup=reply_markup,
        )
        return
    query = "_".join(context.args).lower()
    result = get_deep_info(query)
    await update.message.reply_text(result, parse_mode='Markdown')


async def deep_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    key = query.data
    if key == "back_to_menu":
        keyboard = [
            [InlineKeyboardButton(v["title"], callback_data=k)]
            for k, v in vulnerability_insights.items()
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "Seleziona una vulnerabilità per ricevere dettagli e consigli:",
            reply_markup=reply_markup,
        )
        return
    result = get_deep_info(key)
    keyboard = [
        [InlineKeyboardButton("🔙 Torna indietro", callback_data="back_to_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(text=result, parse_mode='Markdown', reply_markup=reply_markup)


def get_deep_handlers():
    return [
        CommandHandler("deep", deep_command),
        CallbackQueryHandler(deep_callback, pattern=r'^[a-z0-9_]+$'),
    ]
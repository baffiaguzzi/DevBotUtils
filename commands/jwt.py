import jwt
import base64
import json
from datetime import datetime, timezone
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError, ImmatureSignatureError
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode
from .log_utils import append_log_entry


COMMON_KEYS = [
    "secret", "password", "123456", "admin", "jwtsecret", "key", "default",
    "password123", "letmein", "abc123", "qwerty", "123456789", "secret123",
    "passw0rd", "mypassword", "1234", "12345", "000000"
]


def is_base64url(token_part: str) -> bool:
    try:
        base64.urlsafe_b64decode(token_part + '=' * (-len(token_part) % 4))
        return True
    except Exception:
        return False


def format_unix_timestamp(ts):
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return str(ts)


def analyze_claims(payload: dict) -> str:
    report = ""
    now_ts = datetime.now(tz=timezone.utc).timestamp()
    
    for time_field in ['iat', 'exp', 'nbf']:
        if time_field in payload:
            formatted = format_unix_timestamp(payload[time_field])
            if time_field == 'exp':
                expired = payload['exp'] < now_ts
                status = "🔴 Token scaduto!" if expired else "🟢 Token valido"
                report += f"⌛ <b>{time_field}</b>: {formatted} ({status})\n"
            elif time_field == 'nbf':
                not_yet_valid = payload['nbf'] > now_ts
                status = "🔴 Token non ancora valido!" if not_yet_valid else "🟢 Token attivo"
                report += f"⌛ <b>{time_field}</b>: {formatted} ({status})\n"
            else:
                report += f"⌛ <b>{time_field}</b>: {formatted}\n"
                
    for key in ['username', 'sub', 'role', 'email', 'admin']:
        if key in payload:
            report += f"⭐ <b>{key}</b>: {payload[key]}\n"
            
    if not report:
        report = "ℹ️ Nessun claim speciale rilevato.\n"
        
    report += "\n📦 Payload completo:\n<code>" + json.dumps(payload, indent=2) + "</code>"
    return report


def decode_jwt(token: str) -> str:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return ("❌ Token JWT malformato: il token deve contenere 3 parti separate da '.'\n\n"
                    "Formato corretto: header.payload.signature")
        header_b64, payload_b64, signature_b64 = parts
        
        if not (is_base64url(header_b64) and is_base64url(payload_b64) and is_base64url(signature_b64)):
            return "❌ Il token non sembra valido (base64 malformato)!"
        header = json.loads(base64.urlsafe_b64decode(header_b64 + '=' * (-len(header_b64) % 4)))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=' * (-len(payload_b64) % 4)))
        report = f"🧾 <b>Header</b>:\n<code>{json.dumps(header, indent=2)}</code>\n\n"
        report += analyze_claims(payload) + "\n\n"
        report += "───────────────\n"
        alg = header.get("alg", "").lower()
        
        if alg == "none":
            report += "🚨 <b>ATTENZIONE:</b> Algoritmo <b>none</b> rilevato!\n"
            report += "Nessuna firma presente: gravissima vulnerabilità!\n"
            return report
        
        elif alg == "hs256":
            report += "🔐 Algoritmo HS256 rilevato.\nProvo alcune chiavi comuni per verificare la firma...\n"
            verified = False
            for key in COMMON_KEYS:
                try:
                    jwt.decode(token, key, algorithms=["HS256"])
                    report += f"🚨 Firma <b>verificata</b> con chiave: <code>{key}</code>\n"
                    verified = True
                    break
                except (InvalidTokenError, ExpiredSignatureError, ImmatureSignatureError):
                    continue
            if not verified:
                report += "✅ Nessuna chiave debole trovata nella wordlist.\n"
                
        else:
            report += f"ℹ️ Algoritmo di firma: <b>{alg}</b>\n"
            report += "ℹ️ Verifica firma non supportata per questo algoritmo.\n"
            
        now_ts = datetime.now(tz=timezone.utc).timestamp()
        status = []
        
        if "exp" in payload:
            if payload["exp"] < now_ts:
                status.append("🔴 Token scaduto")
            else:
                status.append("🟢 Token valido")
        else:
            status.append("ℹ️ Nessuna scadenza impostata")

        if "nbf" in payload:
            if payload["nbf"] > now_ts:
                status.append("🔴 Token non ancora valido")
            else:
                status.append("🟢 Token attivo")
        if alg == "hs256" and verified:
            status.append("✅ Firma verificata")
        elif alg == "hs256" and not verified:
            status.append("❌ Firma non verificata")
        elif alg == "none":
            status.append("⚠️ Nessuna firma")
        report += "\n───────────────\n"
        report += "📊 Sintesi finale: " + ", ".join(status)
        return report
    
    except Exception as e:
        return f"❌ Errore durante l'analisi del JWT: {str(e)}!"

    
async def jwt_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"Comando /jwt lanciato")
    msg = update.effective_message
    
    if msg is None:
        return
    user = update.effective_user
    token = ' '.join(context.args or []).strip()
    
    if not token:
        await msg.reply_text(
            "📥 Inserisci un JWT da analizzare: `/jwt <token>`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    result = decode_jwt(token)
    append_log_entry("jwt", user.id, user.username or "", token, result)
    await msg.reply_text(result, parse_mode=ParseMode.HTML)

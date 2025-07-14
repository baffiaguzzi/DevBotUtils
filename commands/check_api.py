import json
import aiohttp
import os
import csv
import requests
from datetime import datetime
from telegram import Update
from telegram.ext import ContextTypes
from urllib.parse import urlparse, parse_qsl
from .log_utils import append_log_entry


TEMPLATE_FILE = "templates.json"
LOG_FILE = "logs/api_pro_log.csv"


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def analyze_content_for_errors(content: str) -> list:
    keywords = ["error", "exception", "warning", "fail", "unauthorized", "forbidden", "not found"]
    return [kw for kw in keywords if kw in content.lower()]


def analyze_headers(headers: dict) -> tuple:
    sensitive_headers = []
    security_issues = []
    security_headers = {
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    }
    for h in headers:
        if h.lower() in ["server", "x-powered-by"]:
            sensitive_headers.append(f"{h}: {headers[h]}")
    for req in security_headers:
        if req not in map(str.lower, headers.keys()):
            security_issues.append(req)
    grade = f"{len(security_headers) - len(security_issues)}/{len(security_headers)} header di sicurezza presenti"
    return sensitive_headers, security_issues, grade


def save_template(name: str, data: dict):
    if os.path.exists(TEMPLATE_FILE):
        with open(TEMPLATE_FILE, "r") as f:
            templates = json.load(f)
    else:
        templates = {}
    templates[name] = data
    with open(TEMPLATE_FILE, "w") as f:
        json.dump(templates, f, indent=2)


def load_template(name: str) -> dict:
    if not os.path.exists(TEMPLATE_FILE):
        return {}
    with open(TEMPLATE_FILE, "r") as f:
        templates = json.load(f)
    return templates.get(name, {})


def log_request(data: dict):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    file_exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, "a", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=data.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)
        

def handle_check_api(update, context):
    message = update.message.text
    lines = message.strip().split(maxsplit=3)  
    
    if len(lines) < 3:
        update.message.reply_text("❌ Usa il formato: /api_pro [METODO] [URL] [BODY opzionale]")
        return
    
    method = lines[1].upper()
    url = lines[2]
    raw_body = lines[3] if len(lines) > 3 else None
    headers = {}
    body = None
    
    if raw_body:
        if raw_body.startswith("form:"):
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            form_str = raw_body[len("form:"):]
            body = dict(parse_qsl(form_str))
        else:
            headers["Content-Type"] = "application/json"
            try:
                body = json.loads(raw_body)
            except json.JSONDecodeError:
                update.message.reply_text("❌ JSON non valido. Correggi la sintassi.")
                return
            
    try:
        response = requests.request(method, url, headers=headers, data=body if headers["Content-Type"] == "application/x-www-form-urlencoded" else json.dumps(body) if body else None, timeout=10)        
        status = f"📟 Metodo: {method}\n📟 Status Code: {response.status_code}"
        content_preview = response.text[:1000] 
        update.message.reply_text(f"🔍 Risultato per {url}:\n{status}\n\n📄 Anteprima contenuto:\n{content_preview}")
    
    except requests.exceptions.RequestException as e:
        update.message.reply_text(f"❌ Errore nella richiesta:\n{str(e)}")


async def check_api_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"Comando /api_pro lanciato")
    user = update.effective_user
    msg = update.effective_message
    args = context.args
    
    if not args:
        await update.effective_message.reply_text(
            "❌ Devi specificare almeno l'URL!\nUso:\n"
            "/api_pro [METHOD] <URL> [AUTH_TYPE] [TOKEN] [PAYLOAD_JSON|form:x=1&y=2] [TIMEOUT] [ASSERT] [SAVE_AS=name]"
        )
        return
    
    method = "GET"
    url = ""
    auth_type = None
    token = None
    payload = None
    timeout = 10
    assert_expression = None
    save_as = None
    headers = {}
    
    if args[0].startswith("template:"):
        template_name = args[0].split(":", 1)[1]
        template_data = load_template(template_name)
        if not template_data:
            await update.effective_message.reply_text(f"❌ Template '{template_name}' non trovato!")
            return
        
        method = template_data.get("method", "GET")
        url = template_data.get("url")
        auth_type = template_data.get("auth_type")
        token = template_data.get("token")
        payload = template_data.get("payload")
        timeout = template_data.get("timeout", 10)
        assert_expression = template_data.get("assert")
        content_type = template_data.get("content_type", "application/json")
        
    else:
        method = args[0].upper() if args[0].upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"] else "GET"
        url = args[1 if method != "GET" else 0]
        content_type = "application/json"
        
        for arg in args[2:]:
            if arg in ["Bearer", "Basic"]:
                auth_type = arg
            elif auth_type and not token:
                token = arg
            elif arg.startswith("form:"):
                content_type = "application/x-www-form-urlencoded"
                payload = dict(parse_qsl(arg[len("form:"):]))
            elif arg.startswith("{"):
                try:
                    payload = json.loads(arg)
                    content_type = "application/json"
                except: pass
            elif arg.isdigit():
                timeout = int(arg)
            elif arg.startswith("assert="):
                assert_expression = arg.replace("assert=", "")
            elif arg.startswith("SAVE_AS="):
                save_as = arg.replace("SAVE_AS=", "")
                
    url = normalize_url(url)
    headers["Content-Type"] = content_type
    
    if auth_type and token:
        headers["Authorization"] = f"{auth_type} {token}"
    await update.effective_message.reply_text(f"🔍 Eseguo {method} su {url} con timeout {timeout}s...")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.request(method, url, headers=headers, 
                                        json=payload if content_type == "application/json" else None,
                                        data=payload if content_type == "application/x-www-form-urlencoded" else None,
                                        timeout=timeout) as resp:
                status = resp.status
                resp_headers = dict(resp.headers)
                content = await resp.text()
        sensitive_headers, security_issues, grade = analyze_headers(resp_headers)
        errors_found = analyze_content_for_errors(content)
        md = f"🔍 *Risultato per* [{url}]({url}):\n"
        md += f"📟 *Metodo:* {method}\n📟 *Status Code:* {status}\n\n"
        
        if sensitive_headers:
            md += f"⚠️ *Header sensibili trovati:* {', '.join([h.split(':')[0] for h in sensitive_headers])}\n"
        else:
            md += "✅ Nessun header sensibile rilevato.\n"
        if security_issues:
            md += f"❌ *Header di sicurezza mancanti:* {', '.join(security_issues)}!\n"
        else:
            md += "✅ Tutti gli header di sicurezza essenziali sono presenti.\n"
        md += f"🏅 *Security Headers Grade:* {grade}\n\n"
        if errors_found:
            md += f"🚨 *Errori rilevati nel contenuto:* {', '.join(errors_found)}\n\n"
        else:
            md += "✅ Nessun errore evidente rilevato nel contenuto.\n\n"
        if assert_expression:
            try:
                assertion_result = eval(assert_expression.replace("status", str(status)))
                if assertion_result:
                    md += f"✅ *Asserzione superata:* `{assert_expression}`\n"
                else:
                    md += f"❌ *Asserzione fallita:* `{assert_expression}`\n"
            except Exception as ex:
                md += f"⚠️ *Errore nell'asserzione:* {ex}\n"
        preview = content.strip().replace("\n", " ")
        
        if len(preview) > 500:
            preview = preview[:500] + "..."
        md += f"📄 *Anteprima contenuto:* \n`{preview}`"
        await update.effective_message.reply_text(md, parse_mode="Markdown")
        
        append_log_entry(
            "api_pro",
            user.id,
            user.username or "",
            url,
            md
        )
        
        log_request({
            "timestamp": datetime.now().isoformat(),
            "method": method,
            "url": url,
            "status": status,
            "auth_type": auth_type or "",
            "has_payload": bool(payload),
            "security_grade": grade,
            "errors_found": ",".join(errors_found)
        })
        
        if save_as:
            save_template(save_as, {
                "method": method,
                "url": url,
                "auth_type": auth_type,
                "token": token,
                "payload": payload,
                "timeout": timeout,
                "assert": assert_expression,
                "content_type": content_type
            })
            
    except Exception as e:
        error_msg = f"❌ Errore durante la richiesta a {url}:\n`{str(e)}`!"
        await msg.reply_text(error_msg, parse_mode="Markdown")
        append_log_entry(
            "api_pro_error",
            user.id,
            user.username or "",
            url,
            error_msg
        )
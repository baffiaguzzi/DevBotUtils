import aiohttp
import asyncio
from datetime import datetime
from telegram import Update
from telegram.ext import ContextTypes


SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
]


def valutazione_sicurezza_api(res):
    score = 0
    if res["reachable"]:
        score += 1
    if res["status_code"] and 200 <= res["status_code"] < 300:
        score += 1
    if res["cors"]:
        score += 1
    if res["valid_json"]:
        score += 1
    if res["security_headers"]:
        score += len(res["security_headers"]) 
    if score >= 6:
        return "🔒 Sicurezza API: Ottima"
    elif score >= 4:
        return "⚠️ Sicurezza API: Media"
    else:
        return "❌ Sicurezza API: Critica"


def suggerimenti_api(res):
    sugger = []
    if not res["reachable"]:
        sugger.append("Verifica che l'API sia raggiungibile e online.")
    if not res["status_code"] or not (200 <= res["status_code"] < 300):
        sugger.append("Controlla che l'API restituisca un codice di stato HTTP 2xx.")
    if not res["cors"]:
        sugger.append("Abilita CORS per consentire richieste cross-origin sicure.")
    if not res["valid_json"]:
        sugger.append("Assicurati che l'API restituisca una risposta JSON valida.")
    if not res["security_headers"]:
        sugger.append("Aggiungi header di sicurezza come HSTS, CSP, X-Frame-Options, ecc.")
    else:
        headers_presenti = set(res["security_headers"])
        headers_mancanti = [h for h in SECURITY_HEADERS if h not in headers_presenti]
        if headers_mancanti:
            sugger.append("Aggiungi i seguenti header di sicurezza mancanti: " + ", ".join(headers_mancanti))
    if not res["https"]:
        sugger.append("Utilizza HTTPS per proteggere le comunicazioni.")
    if not res["cache_control"]:
        sugger.append("Specifica header 'Cache-Control' per una gestione ottimale della cache.")
    if res["x_powered_by"]:
        sugger.append(f"Evita di esporre il backend tramite l'header 'X-Powered-By: {res['x_powered_by']}'.")
    if not res["user_agent_accepted"]:
        sugger.append("Il server potrebbe rifiutare richieste con User-Agent personalizzato.")
    if sugger:
        return "💡 Suggerimenti:\n- " + "\n- ".join(sugger)
    return ""


async def analyze_api(url, timeout=10, max_retries=3):
    result = {
        "url": url,
        "reachable": False,
        "status_code": None,
        "response_time_ms": None,
        "content_type": None,
        "valid_json": False,
        "json_type": None,
        "json_keys": [],
        "json_keys_info": {},
        "cors": False,
        "security_headers": [],
        "possible_errors": [],
        "error": None,
        "https": url.startswith("https"),
        "cache_control": False,
        "server_header": None,
        "auth_required": False,
        "x_powered_by": None,
        "user_agent_accepted": True,
        "response_size": None,
        "allowed_methods": [], 
        "post_test_status": None, 
        "post_test_response": None, 
    }
    
    headers = {
        "User-Agent": "SecurityScannerBot/1.0"
    }
    
    async def fetch_with_retries(method, url, **kwargs):
        attempt = 0
        while attempt < max_retries:
            try:
                async with aiohttp.ClientSession(headers=headers) as session:
                    async with session.request(method, url, timeout=timeout, **kwargs) as resp:
                        return resp
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                attempt += 1
                if attempt >= max_retries:
                    raise
                await asyncio.sleep(2 ** attempt) 
                
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            try:
                async with session.options(url, timeout=timeout) as resp_opt:
                    allow = resp_opt.headers.get("Allow")
                    if allow:
                        result["allowed_methods"] = [m.strip() for m in allow.split(",")]
            except Exception as e_opt:
                pass
            
        test_url = url
        if "?" in url:
            test_url += "&test=1"
        else:
            test_url += "?test=1"
        start = datetime.now()
        resp = await fetch_with_retries("GET", test_url)
        end = datetime.now()
        
        result["reachable"] = True
        result["status_code"] = resp.status
        result["response_time_ms"] = int((end - start).total_seconds() * 1000)
        result["content_type"] = resp.headers.get("Content-Type", "")
        result["response_size"] = resp.content_length
        result["server_header"] = resp.headers.get("Server")
        result["x_powered_by"] = resp.headers.get("X-Powered-By")
        result["auth_required"] = "WWW-Authenticate" in resp.headers
        result["cache_control"] = "Cache-Control" in resp.headers
        
        for h in SECURITY_HEADERS:
            if h in resp.headers:
                result["security_headers"].append(h)
        cors_origin = resp.headers.get("Access-Control-Allow-Origin")
        result["cors"] = cors_origin is not None
        
        if "application/json" in result["content_type"].lower():
            try:
                data = await resp.json(content_type=None)
                result["valid_json"] = True
                result["json_type"] = type(data).__name__
                
                if isinstance(data, dict):
                    result["json_keys"] = list(data.keys())
                    for k, v in data.items():
                        tipo = type(v).__name__
                        dim = None
                        if isinstance(v, (list, dict, str)):
                            try:
                                dim = len(v)
                            except:
                                pass
                        result["json_keys_info"][k] = {"type": tipo, "size": dim}
                        
                    for err_key in ("error", "errors", "message", "status", "code"):
                        if err_key in data:
                            result["possible_errors"].append(f"{err_key}: {data[err_key]}")
                            
                elif isinstance(data, list):
                    result["json_keys"] = ["[array di elementi]"]
                else:
                    result["json_keys"] = [f"[{result['json_type']}]"]
                    
            except Exception as e:
                result["valid_json"] = False
                result["error"] = f"Errore parsing JSON: {str(e)}"
                
        if "POST" in result["allowed_methods"]:
            post_test_payload = {"test": "value"}
            try:
                resp_post = await fetch_with_retries(
                    "POST", url, json=post_test_payload, timeout=timeout
                )
                result["post_test_status"] = resp_post.status
                try:
                    result["post_test_response"] = await resp_post.text()
                except:
                    result["post_test_response"] = "[non leggibile]"
            except Exception as e_post:
                result["post_test_status"] = None
                result["post_test_response"] = f"Errore durante POST di test: {str(e_post)}"

    except aiohttp.ClientResponseError as cre:
        result["user_agent_accepted"] = False
        result["error"] = str(cre)
    except Exception as e:
        result["error"] = str(e)
    return result


def format_api_result(res):
    if res["error"]:
        return f"❌ Errore API: {res['error']}!"
    
    msg = (
        f"🔍 Analisi API: {res['url']}\n"
        f"📶 Stato HTTP: {res['status_code']}\n"
        f"⏱️ Tempo risposta: {res['response_time_ms']} ms\n"
        f"🗂️ Content-Type: {res['content_type']}\n"
        f"📦 Dimensione risposta: {res['response_size']} byte\n"
        f"🌐 HTTPS: {'✅' if res['https'] else '❌'}\n"
        f"🛰️ CORS abilitato: {'✅' if res['cors'] else '❌'}\n"
        f"🔐 Headers di sicurezza trovati: {', '.join(res['security_headers']) if res['security_headers'] else 'Nessuno'}\n"
        f"🧠 Cache-Control presente: {'✅' if res['cache_control'] else '❌'}\n"
        f"🔒 Richiesta autenticazione: {'✅' if res['auth_required'] else '❌'}\n"
        f"🛠️ Server: {res['server_header'] or 'N/D'}\n"
        f"⚙️ X-Powered-By: {res['x_powered_by'] or 'N/D'}\n"
        f"📦 JSON valido: {'✅' if res['valid_json'] else '❌'}\n"
    )
    
    if res["valid_json"]:
        msg += f"📊 Tipo JSON: {res['json_type']}\n"
        if res["json_keys"]:
            keys_info_str = []
            for k in res["json_keys"][:10]:
                info = res["json_keys_info"].get(k, {})
                tipo = info.get("type", "?")
                size = info.get("size")
                size_str = f", dimensione: {size}" if size is not None else ""
                keys_info_str.append(f"{k} ({tipo}{size_str})")
            msg += "🔑 Chiavi top-level (max 10): " + ", ".join(keys_info_str) + "\n"
            
    if res["possible_errors"]:
        msg += "⚠️ Possibili errori API trovati:\n"
        for err in res["possible_errors"]:
            msg += f"  - {err}\n"    
    if res.get("allowed_methods"):
        msg += "🛠️ Metodi HTTP supportati: " + ", ".join(res["allowed_methods"]) + "\n"
    if res.get("post_test_status") is not None:
        msg += f"🚀 POST di test: HTTP {res['post_test_status']}\n"
        snippet = res['post_test_response'][:300].replace("\n", " ")
        msg += f"Risposta POST: {snippet}...\n"
        
    msg += "\n" + valutazione_sicurezza_api(res)
    msg += "\n" + suggerimenti_api(res)
    return msg


def normalize_url(url: str) -> str:
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url


async def api_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message or update.effective_message
    if not message:
        return
    if not context.args:
        await message.reply_text("⚠️ Usa: /api_easy <url>")
        return
    url = context.args[0]
    url = normalize_url(url)     
    result = await analyze_api(url)
    msg = format_api_result(result)
    await message.reply_text(msg, parse_mode="Markdown")
import requests
import socket
import ssl
from urllib.parse import urlparse, urlencode
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from urllib.parse import urlparse, urlunparse
from .log_utils import append_log_entry


def normalize_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        return 'https://' + url
    return url


def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        checks = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'XFO',
            'X-Content-Type-Options': 'XCTO',
            'Referrer-Policy': 'Referrer',
            'Permissions-Policy': 'Permissions'
        }
        results = {}
        for header, name in checks.items():
            results[name] = headers.get(header, 'MISSING')
        return results
    except Exception as e:
        return {'error': f'❌ Header check error: {str(e)}!'}


def test_open_redirect(base_url, param='redirect'):
    try:
        parsed = urlparse(base_url)
        query = {param: 'http://evil.com'}
        url_with_redirect = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(query)}"
        response = requests.get(url_with_redirect, allow_redirects=False, timeout=5)
        location = response.headers.get('Location', '')
        if 'evil.com' in location:
            return 'VULNERABLE'
        else:
            return 'Not vulnerable'
    except Exception as e:
        return f'❌ Open Redirect test error: {str(e)}!'


def check_ssl_certificate(hostname, port=443):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return {'error': f'❌ SSL check error: {str(e)}!'}


def scan_common_ports(hostname, ports=[80, 443, 22, 21, 25, 3306]):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((hostname, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports


def run_security_checks(url):
    result = {}
    result['https'] = url.startswith('https://')
    headers_dict = check_security_headers(url)
    result['security_headers'] = headers_dict
    result['open_redirect'] = test_open_redirect(url)
    parsed = urlparse(url)
    cert = check_ssl_certificate(parsed.hostname)
    
    if isinstance(cert, dict) and 'error' in cert:
        result['ssl_error'] = cert['error']
    else:
        result['ssl_issuer'] = cert.get('issuer', 'N/A')
        
    result['open_ports'] = scan_common_ports(parsed.hostname)
    result['cors'] = 'N/D' 
    return result


def generate_security_advice(analysis, open_ports):
    advice = "\n💡 Consigli di sicurezza:\n"
    if not analysis.get('https', False):
        advice += "- ⚠️ Il sito NON usa HTTPS, attivarlo è fondamentale per proteggere i dati in transito.\n"
    else:
        advice += "- ✅ HTTPS è attivo, ottimo per la sicurezza della connessione.\n"
        
    cors = analysis.get('cors', 'N/D')
    if cors == 'N/D':
        advice += "- ⚠️ Non è stato possibile verificare la configurazione CORS.\n"
    elif cors.lower() in ['true', 'enabled', 'yes', 'allow-all']:
        advice += "- ⚠️ Attenzione: CORS è abilitato in modo permissivo, potrebbe permettere richieste da origini non autorizzate.\n"
    else:
        advice += "- ✅ CORS sembra configurato correttamente.\n"
        
    headers = analysis.get('security_headers', {})
    missing_headers = [k for k,v in headers.items() if v == 'MISSING']
    if missing_headers:
        advice += f"- ⚠️ Mancano header di sicurezza importanti: {', '.join(missing_headers)}. Aggiungerli aiuta a mitigare attacchi XSS, clickjacking e altri.\n"
    else:
        advice += "- ✅ Tutti gli header di sicurezza fondamentali sono presenti.\n"
    if analysis.get('open_redirect', 'N/D') == 'VULNERABLE':
        advice += "- 🚨 Il sito è vulnerabile a open redirect: correggere subito il problema per evitare phishing.\n"
    else:
        advice += "- ✅ Open redirect non rilevato.\n"
        
    ssl_cert = analysis.get('ssl_certificate', {})
    if 'error' in ssl_cert:
        advice += f"- ⚠️ Problema con il certificato SSL: {ssl_cert['error']}\n"
    else:
        advice += "- ✅ Certificato SSL valido e emesso da una CA riconosciuta.\n"
        
    risky_ports = [21, 22, 23, 25, 3306, 3389]
    open_risky_ports = [p for p in open_ports if p in risky_ports]
    if open_risky_ports:
        advice += f"- ⚠️ Sono aperte porte potenzialmente rischiose: {', '.join(str(p) for p in open_risky_ports)}. Verifica che siano necessarie e ben protette.\n"
    else:
        advice += "- ✅ Nessuna porta critica aperta visibile.\n"
    return advice


async def security_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"Comando /security lanciato")
    msg = update.effective_message
    user = update.effective_user

    if not context.args:
        if msg:
            await msg.reply_text("⚠️ Usa: /security <url>")
        append_log_entry(
            "security",
            user.id,
            user.username or "",
            "url=N/D",
            "Argomento mancante nel comando"
        )
        return

    url = normalize_url(context.args[0])

    append_log_entry(
        "security",
        user.id,
        user.username or "",
        f"url={url}",
        "Avvio analisi sicurezza"
    )

    try:
        analysis = run_security_checks(url)
    except Exception as e:
        result = f"❌ Errore durante l'analisi sicurezza: {e}!"
        append_log_entry(
            "security",
            user.id,
            user.username or "",
            f"url={url}",
            f"Errore: {str(e)}"
        )
    else:
        open_ports = analysis.get('open_ports', [])
        result = f"🔐 Analisi sicurezza per {url}:\n"
        result += f"✅ HTTPS: {analysis.get('https', 'N/D')}\n"
        result += f"❌ CORS abilitato: {analysis.get('cors', 'N/D')}!\n"
        result += f"🔐 Header di sicurezza: {', '.join(f'{k}: {v}' for k,v in analysis.get('security_headers', {}).items())}\n"
        result += f"🔴 Open redirect: {analysis.get('open_redirect', 'N/D')}\n"
        if 'ssl_error' in analysis:
            result += f"❌ Errore SSL: {analysis['ssl_error']}!\n"
        else:
            result += f"🔐 SSL issuer: {analysis.get('ssl_issuer', 'N/D')}\n"
        result += f"🔓 Porte aperte: {', '.join(str(p) for p in open_ports) if open_ports else 'Nessuna'}\n"
        result += generate_security_advice(analysis, open_ports)

        append_log_entry(
            "security",
            user.id,
            user.username or "",
            f"url={url}",
            f"Analisi completata. Porte aperte: {len(open_ports)}"
        )

    if msg:
        await msg.reply_text(result)
    else:
        print("Impossibile rispondere: update.effective_message è None")

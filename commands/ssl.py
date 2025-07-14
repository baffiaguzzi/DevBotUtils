import ssl
import socket
import asyncio
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import aiohttp
from telegram import Update
from telegram.ext import ContextTypes
from datetime import timezone
from cryptography.x509.oid import SignatureAlgorithmOID
from OpenSSL import SSL
from cryptography.x509 import load_der_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import socket
import dns.resolver
from .log_utils import append_log_entry


async def fetch_ssl_info(domain, port=443, timeout=5):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    loop = asyncio.get_event_loop()
    
    def _get_cert():
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True) 
                tls_version = ssock.version()
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
                issuer = cert.issuer
                subject = cert.subject
                
                def get_attr(name, x509name):
                    try:
                        return x509name.get_attributes_for_oid(name)[0].value
                    except IndexError:
                        return None
                    
                issuer_org = get_attr(x509.NameOID.ORGANIZATION_NAME, issuer) or "Sconosciuto"
                subject_cn = get_attr(x509.NameOID.COMMON_NAME, subject) or "Sconosciuto"
                wildcard = subject_cn.startswith("*.")
                
                return {
                    "not_before": not_before,
                    "not_after": not_after,
                    "issuer_org": issuer_org,
                    "subject_cn": subject_cn,
                    "wildcard": wildcard,
                    "tls_version": tls_version,
                    "cert_obj": cert, 
                }
    try:
        result = await loop.run_in_executor(None, _get_cert)
    except Exception as e:
        return {"error": f"❌ Impossibile ottenere certificato SSL: {e}!"}
    return result


async def check_http_redirect(domain):
    url = f"http://{domain}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, allow_redirects=False, timeout=5) as resp:
                location = resp.headers.get("Location", "")
                if resp.status in (301, 302) and location.startswith("https://"):
                    return True
    except Exception:
        pass
    return False


async def get_hsts_header(domain):
    url = f"https://{domain}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.head(url, timeout=5) as resp:
                hsts = resp.headers.get("Strict-Transport-Security", "Assente")
                return hsts
    except Exception:
        return "Assente"


async def analyze_ssl(domain):
    ssl_info = await fetch_ssl_info(domain)
    if "error" in ssl_info:
        return ssl_info   
    
    cert = ssl_info.get("cert_obj")
    sig_algo_name, key_size = None, None
    if cert:
        sig_algo_name, key_size = get_cert_signature_and_key_info(cert)
        
    now = datetime.datetime.now(timezone.utc)
    not_before = ssl_info.get("not_before")
    not_after = ssl_info.get("not_after")
    days_left = (not_after - now).days if not_after else -1
    redirect = await check_http_redirect(domain)
    hsts = await get_hsts_header(domain)    
    loop = asyncio.get_event_loop()
    chain = await loop.run_in_executor(None, get_cert_chain, domain)
    http2 = await loop.run_in_executor(None, check_http2_support, domain)
    caa_records = await loop.run_in_executor(None, get_caa_records, domain)
    tls_versions_to_test = [
        ssl.TLSVersion.TLSv1,
        ssl.TLSVersion.TLSv1_1,
        ssl.TLSVersion.TLSv1_2,
        ssl.TLSVersion.TLSv1_3
    ]
    tls_results = {}
    
    for version in tls_versions_to_test:
        supported, cipher = await loop.run_in_executor(None, test_tls_version, domain, 443, version)
        tls_results[str(version)] = {"supported": supported, "cipher": cipher}
        
    return {
        "cert_not_before": not_before.strftime("%Y-%m-%d") if not_before else "?",
        "cert_not_after": not_after.strftime("%Y-%m-%d") if not_after else "?",
        "cert_days_left": days_left,
        "cert_issuer": {"organizationName": ssl_info.get("issuer_org", "Sconosciuto")},
        "cert_subject": {"commonName": ssl_info.get("subject_cn", "Sconosciuto")},
        "cert_wildcard": ssl_info.get("wildcard", False),
        "tls_versions_supported": [ssl_info.get("tls_version")] if ssl_info.get("tls_version") else [],
        "http_to_https_redirect": redirect,
        "hsts_header": hsts,
        "cert_signature_algorithm": sig_algo_name or "Sconosciuto",
        "cert_public_key_size": key_size or "Sconosciuta",
        "cert_chain": chain,
        "http2_supported": http2,
        "caa_records": caa_records,
        "tls_versions_tested": tls_results
    }
    
    
def get_cert_chain(domain, port=443):
    ctx = SSL.Context(SSL.TLS_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *x: True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = SSL.Connection(ctx, sock)
    conn.set_tlsext_host_name(domain.encode())
    conn.connect((domain, port))
    conn.do_handshake()
    certs = conn.get_peer_cert_chain() 
    chain = []
    
    for cert in certs:
        cert_cryptography = cert.to_cryptography()
        der_bytes = cert_cryptography.public_bytes(serialization.Encoding.DER)
        x509_cert = load_der_x509_certificate(der_bytes, default_backend())
        chain.append(x509_cert)
        
    conn.close()
    sock.close()
    return chain


def get_caa_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CAA')
        caa_records = [r.to_text() for r in answers]
        return caa_records
    except dns.resolver.NoAnswer:
        return []
    except Exception as e:
        return [f"❌ Errore: {e}!"]
    
    
def check_http2_support(domain, port=443):
    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2', 'http/1.1'])
    try:
        with socket.create_connection((domain, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                selected_proto = ssock.selected_alpn_protocol()
                return selected_proto == 'h2'
    except Exception:
        return False


def test_tls_version(domain, port=443, tls_version=ssl.TLSVersion.TLSv1_2):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = tls_version
    context.maximum_version = tls_version
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return True, ssock.cipher()
    except Exception:
        return False, None


def get_cert_signature_and_key_info(cert):
    sig_algo_oid = cert.signature_algorithm_oid
    sig_algo_name = sig_algo_oid._name if hasattr(sig_algo_oid, '_name') else str(sig_algo_oid)
    pub_key = cert.public_key()
    key_size = None
    if hasattr(pub_key, 'key_size'):
        key_size = pub_key.key_size
    elif hasattr(pub_key, 'curve'):
        key_size = pub_key.curve.key_size
    return sig_algo_name, key_size


def valutazione_sicurezza(result):
    days_left = result.get("cert_days_left", -1)
    hsts = result.get("hsts_header")
    redirect = result.get("http_to_https_redirect", False)
    tls_versions = result.get("tls_versions_supported", [])
    score = 0
    if days_left > 30:
        score += 2
    elif days_left > 0:
        score += 1
    if hsts:
        score += 2
    if redirect:
        score += 1
    if any(ver in ["TLSv1.2", "TLSv1.3"] for ver in tls_versions):
        score += 2
    else:
        score -= 1
    if score >= 6:
        return "🔒 Sicurezza: SSL OK"
    elif score >= 3:
        return "⚠️ Sicurezza: Rischio medio"
    else:
        return "❌ Sicurezza: Critico!"


def suggerimenti(result):
    sugger = []
    if not result.get("hsts_header"):
        sugger.append("Attiva HSTS per migliorare la sicurezza")
    if not result.get("http_to_https_redirect"):
        sugger.append("Abilita redirect HTTP→HTTPS")
    if result.get("cert_days_left", 0) < 15:
        sugger.append("Rinnova il certificato SSL presto")
    if sugger:
        return "💡 Suggerimenti:\n- " + "\n- ".join(sugger)
    return ""


def format_ssl_result(domain, result):
    if "error" in result:
        return f"❌ Errore nell'analisi SSL per {domain}:\n{result['error']}!"
    
    days_left = result.get("cert_days_left", -1)
    days_warning = ""
    if days_left < 0:
        days_warning = "⚠️ Certificato scaduto!"
    elif days_left < 15:
        days_warning = f"⚠️ Certificato scade tra {days_left} giorni!"
        
    tls_versions = ", ".join(result.get("tls_versions_supported", [])) or "Nessuna"
    tls_version_names = {
        769: "TLS 1.0",
        770: "TLS 1.1",
        771: "TLS 1.2",
        772: "TLS 1.3",
    }
    
    redirect = "✅ Presente" if result.get("http_to_https_redirect") else "❌ Assente"
    hsts = result.get("hsts_header", "Assente")
    wildcard = "Sì" if result.get("cert_wildcard") else "No"
    sig_algo = result.get("cert_signature_algorithm", "Sconosciuto")
    key_size = result.get("cert_public_key_size", "Sconosciuta")    
    tls_tested = result.get('tls_versions_tested', {})           
    chain = result.get('cert_chain')   
    
    msg = (
        f"🔒 Analisi SSL per: {domain}\n"
        f"🗓️ Validità certificato: {result.get('cert_not_before', '?')} - {result.get('cert_not_after', '?')} {days_warning}\n"
        f"🏢 Emittente: {result.get('cert_issuer', {}).get('organizationName', 'Sconosciuto')}\n"
        f"🎯 Soggetto: {result.get('cert_subject', {}).get('commonName', 'Sconosciuto')}\n"
        f"🌐 Certificato wildcard: {wildcard}\n"
        f"🔐 TLS supportati: {tls_versions}\n"
        f"🖋️ Algoritmo firma: {sig_algo}\n"
        f"🔑 Dimensione chiave pubblica: {key_size} bit\n"
        f"➡️ Redirect HTTP→HTTPS: {redirect}\n"
        f"🔑 Header HSTS: {hsts}\n"
        f"📡 Supporto HTTP/2: {'✅' if result.get('http2_supported') else '❌'}\n"
        f"📜 Record CAA: {', '.join(result.get('caa_records', [])) or 'Nessuno'}\n"
        f"🔍 TLS versions testati:\n"
    )  
    
    msg += "\n" + valutazione_sicurezza(result)
    msg += "\n" + suggerimenti(result)
    ocsp_status = result.get("ocsp_status")
    
    if ocsp_status:
        msg += f"\n📡 Stato OCSP: {ocsp_status}"    
    for tls_ver, info in tls_tested.items():
        tls_ver_int = int(tls_ver)
        name = tls_version_names.get(tls_ver_int, str(tls_ver))
        supported = "✅" if info["supported"] else "❌"
        cipher = info["cipher"][0] if info["cipher"] else "N/A"
        msg += f"   - {name}: {supported}, Cipher: {cipher}\n"        
    if chain:
        msg += f"\n📚 Catena certificati ({len(chain)} certs):\n"
        for i, cert in enumerate(chain, start=1):
            try:
                cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                cn = cn_attr[0].value if cn_attr else "Sconosciuto"
            except Exception:
                cn = "Sconosciuto"
            msg += f"   {i}. {cn}\n"            
    return msg


async def ssl_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"Comando /ssl lanciato")
    message = update.message or update.effective_message
    user = update.effective_user

    if not message:
        return

    if not context.args:
        await message.reply_text("⚠️ Usa: /ssl <dominio>")
        append_log_entry(
            "ssl",
            user.id,
            user.username or "",
            "dominio=N/D",
            "Argomento mancante nel comando"
        )
        return

    domain = context.args[0]
    append_log_entry(
        "ssl",
        user.id,
        user.username or "",
        f"dominio={domain}",
        "Avvio analisi SSL"
    )

    try:
        result = await analyze_ssl(domain)
        msg = format_ssl_result(domain, result)
        await message.reply_text(msg)
        append_log_entry(
            "ssl",
            user.id,
            user.username or "",
            f"dominio={domain}",
            f"Analisi completata. SSL valido: {result.get('valid', 'N/D')} | Emittente: {result.get('issuer', 'N/D')}"
        )
    except Exception as e:
        await message.reply_text(f"❌ Errore durante l'analisi SSL: {str(e)}")
        append_log_entry(
            "ssl",
            user.id,
            user.username or "",
            f"dominio={domain}",
            f"Errore: {str(e)}"
        )

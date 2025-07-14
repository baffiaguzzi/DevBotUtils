import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import ssl
import socket
import datetime
import re
import json
from telegram import Update
from telegram.ext import ContextTypes
from .log_utils import append_log_entry


async def fetch_url(session, url, timeout=10):
    try:
        async with session.get(url, timeout=timeout) as resp:
            content = await resp.text()
            return resp.status, content, resp.headers
    except Exception as e:
        return None, None, None


async def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                notAfter = cert['notAfter']
                expire_date = datetime.datetime.strptime(notAfter, '%b %d %H:%M:%S %Y %Z')
                days_left = (expire_date - datetime.datetime.utcnow()).days
                return True, days_left
    except Exception:
        return False, None


def analyze_headers(headers):
    required = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']
    missing = [h for h in required if h not in headers]
    return missing


def word_count(text):
    words = re.findall(r'\w+', text.lower())
    return len(words)


def keyword_density(text, keywords):
    text = text.lower()
    total_words = word_count(text)
    density = {}
    for kw in keywords:
        count = text.count(kw.lower())
        density[kw] = round(count / total_words * 100, 2) if total_words else 0
    return density


def generate_seo_advice(analysis):
    advice = []
    if analysis['headers']['H1'] == 0:
        advice.append("📌 Aggiungi un tag H1 per definire chiaramente il titolo principale della pagina.")
    if analysis['internal_links'] == 0:
        advice.append("🔗 Inserisci link interni per migliorare la navigazione e l’indicizzazione da parte di Google.")
    if analysis['missing_security_headers']:
        missing = ", ".join(analysis['missing_security_headers'])
        advice.append(f"🔒 Configura header di sicurezza mancanti: {missing}.")
    if not analysis['robots_txt_valid']:
        advice.append("🤖 Correggi il file robots.txt: assicurati che sia un file di testo con regole corrette e non una pagina HTML.")
    if not analysis['json_ld']:
        advice.append("💡 Aggiungi markup JSON-LD per migliorare la visualizzazione nei risultati di ricerca con rich snippet.")
    if analysis['meta_viewport_absent']:
        advice.append("📱 Aggiungi il meta tag viewport per rendere il sito responsive su dispositivi mobili.")
    if not advice:
        return "🎉 Ottimo lavoro! Nessun problema SEO rilevato."
    else:
        return "🔧 Suggerimenti per migliorare la SEO:\n" + "\n".join(advice)


async def analyze_seo(url: str) -> dict:
    if not url.startswith("http"):
        url = "http://" + url
        
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    async with aiohttp.ClientSession() as session:
        status, text, headers = await fetch_url(session, url)
        if status != 200 or not text:
            raise Exception(f"❌ Impossibile accedere alla pagina (HTTP {status})!")
        
        soup = BeautifulSoup(text, 'html.parser')
        title_tag = soup.title.string.strip() if soup.title else ""
        description_tag = soup.find('meta', attrs={'name': 'description'})
        description = description_tag['content'].strip() if description_tag else ""
        headers_count = {}
        
        for i in range(1, 7):
            tags = soup.find_all(f'h{i}')
            headers_count[f'H{i}'] = len(tags)
            
        imgs = soup.find_all('img')
        imgs_no_alt = [img for img in imgs if not img.has_attr('alt') or not img['alt'].strip()]
        imgs_no_alt_count = len(imgs_no_alt)
        all_links = soup.find_all('a', href=True)
        internal_links = 0
        external_links = 0
        nofollow_links = 0
        
        for link in all_links:
            href = link['href']
            if href.startswith('#') or href.startswith('mailto:') or href.startswith('javascript:'):
                continue
            href_parsed = urlparse(urljoin(url, href))
            if href_parsed.netloc == domain:
                internal_links += 1
            else:
                external_links += 1
            rel = link.get('rel', [])
            if 'nofollow' in rel:
                nofollow_links += 1
                
        ssl_valid, ssl_days_left = await check_ssl(domain)
        ssl_status = f"✅ Certificato valido, scade tra {ssl_days_left} giorni" if ssl_valid else "❌ SSL non valido o non trovato!"
        missing_headers = analyze_headers(headers)
        robots_url = f"{parsed_url.scheme}://{domain}/robots.txt"
        status_r, robots_txt, _ = await fetch_url(session, robots_url, timeout=5)
        robots_txt_valid = status_r == 200 and not (robots_txt.strip().startswith('<!DOCTYPE html') or robots_txt.strip().startswith('<html'))
        sitemap_url = f"{parsed_url.scheme}://{domain}/sitemap.xml"
        status_s, _, _ = await fetch_url(session, sitemap_url, timeout=5)
        sitemap_found = status_s == 200
        total_words = word_count(text)
        viewport = soup.find('meta', attrs={'name':'viewport'})
        jsonld = soup.find('script', type='application/ld+json')
        has_jsonld = bool(jsonld)
        
        return {
            "url": url,
            "title": title_tag,
            "title_length": len(title_tag),
            "meta_description": description,
            "meta_description_length": len(description),
            "headers": headers_count,
            "images_without_alt": imgs_no_alt_count,
            "internal_links": internal_links,
            "external_links": external_links,
            "nofollow_links": nofollow_links,
            "ssl_status": ssl_status,
            "missing_security_headers": missing_headers,
            "robots_txt_valid": robots_txt_valid,
            "sitemap_found": sitemap_found,
            "total_words": total_words,
            "meta_viewport_absent": viewport is None,
            "json_ld": has_jsonld
        }


async def seo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"Comando /seo lanciato")
    msg = update.effective_message
    user = update.effective_user

    if not context.args:
        if msg:
            await msg.reply_text("⚠️ Usa: /seo <url>")
        append_log_entry(
            "seo",
            user.id,
            user.username or "",
            "url=N/D",
            "Argomento mancante nel comando"
        )
        return

    url = context.args[0]
    append_log_entry(
        "seo",
        user.id,
        user.username or "",
        f"url={url}",
        "Avvio analisi SEO"
    )

    try:
        analysis = await analyze_seo(url)
    except Exception as e:
        result = f"❌ Errore durante l'analisi SEO: {e}!"
        append_log_entry(
            "seo",
            user.id,
            user.username or "",
            f"url={url}",
            f"Errore: {str(e)}"
        )
    else:
        result = (
            f"🔍 SEO Analisi sito: {analysis['url']}\n"
            f"🏷️ Titolo: {analysis['title']} (lunghezza {analysis['title_length']})\n"
            f"📝 Meta description: {analysis['meta_description']} (lunghezza {analysis['meta_description_length']})\n"
            f"🔖 Header tags: {analysis['headers']}\n"
            f"🖼️ Immagini senza alt: {analysis['images_without_alt']}\n"
            f"🔗 Link interni: {analysis['internal_links']}, esterni: {analysis['external_links']}, nofollow: {analysis['nofollow_links']}\n"
            f"🔒 SSL: {analysis['ssl_status']}\n"
            f"⚠️ Headers di sicurezza mancanti: {', '.join(analysis['missing_security_headers']) if analysis['missing_security_headers'] else 'Nessuno'}\n"
            f"🤖 robots.txt valido: {'Sì' if analysis['robots_txt_valid'] else 'No'}\n"
            f"🗺️ sitemap.xml: {'Trovata' if analysis['sitemap_found'] else 'Non trovata'}\n"
            f"📊 Parole totali pagina: {analysis['total_words']}\n"
            f"📱 Meta viewport: {'Assente' if analysis['meta_viewport_absent'] else 'Presente'}\n"
            f"💡 Markup JSON-LD: {'Presente' if analysis['json_ld'] else 'Assente'}\n\n"
        )
        advice = generate_seo_advice(analysis)
        result += advice

        append_log_entry(
            "seo",
            user.id,
            user.username or "",
            f"url={url}",
            f"Analisi completata. Titolo: '{analysis['title']}' | Images senza alt: {analysis['images_without_alt']}"
        )

    if msg:
        await msg.reply_text(result)
    else:
        print("❌ Impossibile rispondere: update.effective_message è None!")

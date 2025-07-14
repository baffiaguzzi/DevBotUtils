from telegram import Update
from telegram.ext import ContextTypes


vulnerability_insights = {
    "sql_injection": {
        "title": "💉 SQL Injection",
        "description": (
            "La SQL Injection è una vulnerabilità che permette a un attaccante di "
            "iniettare comandi SQL malevoli in una query, accedendo o modificando dati sensibili."
        ),
        "solutions": [
            "✅ Usa query parametrizzate/preparate (es. con PDO, SQLAlchemy, Django ORM).",
            "✅ Evita la concatenazione diretta di input utente nelle query.",
            "✅ Valida e filtra tutti gli input dell'utente.",
            "✅ Applica il principio del minimo privilegio al database."
        ]
    },
    "directory_traversal": {
        "title": "📁 Directory Traversal",
        "description": (
            "Permette a un attaccante di accedere a file al di fuori della directory prevista "
            "navigando tramite sequenze ../ nel percorso dei file."
        ),
        "solutions": [
            "✅ Normalizza i percorsi ed escludi input contenenti '../' o simili.",
            "✅ Usa whitelist di nomi file sicuri.",
            "✅ Non usare input utente direttamente nei percorsi dei file.",
            "✅ Isola le directory accessibili dagli utenti."
        ]
    },
    "lfi": {
        "title": "📄 Local File Inclusion (LFI)",
        "description": (
            "LFI consente di includere file locali arbitrari nel server, "
            "portando spesso a leakage di informazioni o esecuzione di codice."
        ),
        "solutions": [
            "✅ Limita gli input dell’utente a file specifici (whitelist).",
            "✅ Disabilita l’inclusione dinamica non necessaria.",
            "✅ Controlla i file inclusi con regex sicure.",
            "✅ Usa percorsi assoluti e directory protette."
        ]
    },
    "rfi": {
        "title": "🌍 Remote File Inclusion (RFI)",
        "description": (
            "Simile a LFI, ma consente l'inclusione di file remoti. "
            "Può portare all'esecuzione di codice remoto sul server."
        ),
        "solutions": [
            "✅ Disabilita `allow_url_include` in PHP o configurazioni simili.",
            "✅ Mai fidarsi di URL forniti dall'utente per includere file.",
            "✅ Usa un sistema di routing e template sicuro.",
            "✅ Filtra, valida e sanitizza ogni input."
        ]
    },
    "command_injection": {
        "title": "💣 Command Injection",
        "description": (
            "Permette a un attaccante di eseguire comandi di sistema "
            "arbitrari passando input malevoli a funzioni come os.system."
        ),
        "solutions": [
            "✅ Usa librerie sicure come `subprocess.run` con `shell=False` in Python.",
            "✅ Non concatenare comandi con input utente.",
            "✅ Escapa e valida gli input se assolutamente necessario usarli.",
            "✅ Riduci i privilegi dei processi."
        ]
    },
    "host_header_injection": {
        "title": "🔗 Host Header Injection",
        "description": (
            "Modificando l'header Host, un attaccante può bypassare controlli, generare link malevoli o eseguire attacchi SSRF."
        ),
        "solutions": [
            "✅ Valida l'header Host e confrontalo con un valore atteso.",
            "✅ Evita di usarlo per costruire URL dinamici.",
            "✅ Usa un reverse proxy con header sicuri.",
            "✅ Imposta header `X-Forwarded-Host` con attenzione."
        ]
    },
    "xss": {
        "title": "🧪 Cross-Site Scripting (XSS)",
        "description": (
            "L'XSS consente l'iniezione di codice JavaScript malevolo, "
            "che può rubare dati utente o di sessione."
        ),
        "solutions": [
            "✅ Escapa sempre l’output HTML, JS e URL.",
            "✅ Usa Content Security Policy (CSP).",
            "✅ Valida e sanitizza l'input lato client e server.",
            "✅ Usa framework che proteggono da XSS (es. React, Angular)."
        ]
    },
    "csrf": {
        "title": "🔒 Cross-Site Request Forgery (CSRF)",
        "description": (
            "Un attaccante forza l’utente a eseguire azioni indesiderate in un'app dove è autenticato."
        ),
        "solutions": [
            "✅ Usa token CSRF unici per ogni sessione e form.",
            "✅ Valida il Referer/Origin.",
            "✅ Imposta SameSite=Lax o Strict sui cookie.",
            "✅ Autorizza esplicitamente ogni azione sensibile."
        ]
    },
    "open_redirect": {
        "title": "🔁 Open Redirect",
        "description": (
            "Permette a un attaccante di redirigere l’utente verso siti esterni per phishing o tracciamento."
        ),
        "solutions": [
            "✅ Evita di prendere URL di destinazione da input utente.",
            "✅ Usa identificatori interni (es. ID) e mappa le destinazioni server-side.",
            "✅ Valida che gli URL siano interni al dominio.",
            "✅ Mostra un avviso prima di un redirect esterno."
        ]
    },
    "insecure_cookies": {
        "title": "🍪 Insecure Cookies",
        "description": (
            "Cookie non protetti possono essere intercettati o manipolati. "
            "Questo compromette la sicurezza delle sessioni."
        ),
        "solutions": [
            "✅ Imposta i flag `HttpOnly`, `Secure`, e `SameSite` per ogni cookie.",
            "✅ Non salvare dati sensibili direttamente nei cookie.",
            "✅ Cripta i contenuti dei cookie se necessario.",
            "✅ Usa HTTPS per ogni comunicazione."
        ]
    }
}


def get_deep_info(key: str) -> str:
    info = vulnerability_insights.get(key)
    if not info:
        return f"❌ Nessuna informazione trovata per *{key}*!"
    mitigation = "\n".join(info["solutions"]) 
    response = (
        f"🛡️ *{info['title']}*\n\n"
        f"{info['description']}\n\n"
        f"🔧 *Come Mitigare:*\n"
        f"{mitigation}"
    )
    return response


async def deep_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usa: /deep <nome_vulnerabilità>\n(es: /deep sql_injection)")
        return
    key = context.args[0].lower()
    explanation = get_deep_info(key)
    if explanation:
        await update.message.reply_text(explanation, parse_mode="Markdown")
    else:
        await update.message.reply_text("❌ Vulnerabilità non riconosciuta! Prova con: sql_injection, open_redirect, ecc.")
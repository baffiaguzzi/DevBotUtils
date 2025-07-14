# 🤖 DevBotUtils — Telegram Bot for Developers, Ethical Hackers & Sysadmins

**DevBotUtils** is a multifunctional Telegram bot designed to help developers, pentesters, sysadmins, and power users automate diagnostics, testing, and reconnaissance — all directly from Telegram.

No need to install anything locally — everything runs via Telegram commands in the cloud.

---

## 🚀 Features

- 🛰️ Ping & connectivity tests
- 📄 HTTP header inspection
- 🛡️ SSL certificate analysis
- ⚡ Performance metrics (via Lighthouse-like audit)
- 🌐 SEO & metadata audit
- 🔐 Security misconfiguration detection
- 🔍 Vulnerability scanning (XSS, SQLi, LFI, etc.)
- 🧪 REST API testing (Easy & Pro/Postman mode)
- 📡 IP & port scanning (Nmap-like)
- 📶 Wi-Fi LAN scanning (LAN only)
- 🪪 JWT decoding and validation
- 🤖 HTML scraper (titles, links, images)
- 🧬 Injection attacks simulator
- 🕵️ PhpMyAdmin brute-force testing
- 💣 Port brute-forcing
- 📜 Log viewer (daily logs)
- 🧑‍💻 Private mode via Telegram ID whitelist

---

## 🧰 Commands Overview

| Command          | Description                                              |
|------------------|----------------------------------------------------------|
| `/ping`          | Basic ping test on a URL                                 |
| `/analisi`       | General diagnostics for a website                        |
| `/headers`       | Analyze HTTP headers and suggest fixes                   |
| `/ssl`           | Inspect HTTPS certificate and TLS settings               |
| `/performance`   | Audit page performance (Core Web Vitals)                 |
| `/seo`           | Analyze meta tags, robots, sitemap, etc.                 |
| `/vulnerability` | Scan for common OWASP vulnerabilities                    |
| `/security`      | Check for insecure headers, weak SSL, exposed ports      |
| `/api_easy`      | Simple REST API tester                                   |
| `/api_pro`       | Advanced API tester (Postman-style)                      |
| `/ip`            | IP scanner for open ports/services                       |
| `/wifi`          | Wi-Fi LAN scanner (for local networks only)             |
| `/scraper`       | Scrape and extract HTML content                          |
| `/jwt`           | Decode and validate JWT tokens                           |
| `/pentest`       | Brute-force phpMyAdmin login                             |
| `/brute`         | Brute-force scan common ports                            |
| `/inject`        | Simulate SQLi, XSS, and Command Injection                |
| `/log`           | View logs from current session                           |

---

## 🔐 Authorization Mode

The bot is protected by a **Telegram User ID whitelist**.  
Only authorized users (via `.env` or `config.py`) can access the bot and its commands.

---

## ⚙️ Tech Stack

- [Python 3.10+](https://www.python.org/)
- [python-telegram-bot 20+](https://github.com/python-telegram-bot/python-telegram-bot)
- Libraries: `aiohttp`, `dotenv`, `nest_asyncio`, `aioping`
- Modular architecture: `commands/`, `utils/`, `config.py`
- Async execution with `asyncio`
- Inline callback handler for dynamic UI interactions

---

## 🛠️ Getting Started

1. **Clone the repo**  

   ```bash
   git clone https://github.com/your-username/DevBotUtils.git
   cd DevBotUtils
   ```

2. **Install dependencies**  

   ```bash
   pip install -r requirements.txt
   ```

3. **Create a `.env` file** with your bot credentials  

   ```env
   BOT_TOKEN=your_telegram_bot_token
   ALLOWED_USERS=123456789,987654321
   ```

4. **Run the bot**  

   ```bash
   python main.py
   ```

✅ The bot runs in polling mode and will start listening to Telegram commands.

---

## 📁 Project Structure

```bash
📦 DevBotUtils/
├── commands/            # All command handlers (e.g., ping, seo, api)
├── config.py            # Config values and auth logic
├── utils.py             # Shared functions (e.g., decorators, set_commands)
├── main.py              # Entry point of the bot
├── .env                 # Bot token & authorized users
└── README.md
```

---

## 📜 License

**MIT License** © Gabriele Tambellini  
This bot is free and open-source. Use responsibly for educational or professional purposes.

---

## ✨ Contributing

Feel free to fork the repo and create pull requests for improvements or new features.  
If you find this project useful, consider giving it a ⭐️!

---

## 💬 Final Notes

> This project was born to streamline frequent dev/sysadmin tasks with zero setup.  
> A smart, portable assistant — right in your pocket.

Happy hacking! 👨‍💻💥  

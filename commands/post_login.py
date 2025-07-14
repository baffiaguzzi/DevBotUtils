
import aiohttp
import asyncio


async def login_and_scan(target, user, password):
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target
    login_url = target
    session_timeout = aiohttp.ClientTimeout(total=10)
    
    async with aiohttp.ClientSession(timeout=session_timeout) as session:
        try:
            auth = aiohttp.BasicAuth(login=user, password=password)
            async with session.post(login_url, auth=auth, allow_redirects=True) as resp:
                if resp.status == 200:
                    print(f"✅ Login riuscito su {login_url}")
                    cookies = session.cookie_jar.filter_cookies(login_url)
                    cookies_dict = {key: morsel.value for key, morsel in cookies.items()}
                else:
                    print(f"❌ Login fallito: status {resp.status}!")
                    return
                
            protected_paths = [
                "/", "/index.php", "/dashboard", "/phpmyadmin/", "/server_sql.php",
                "/phpmyadmin/sql.php", "/phpmyadmin/db_structure.php", "/phpmyadmin/export.php"
            ]
            
            for path in protected_paths:
                full_url = target.rstrip("/") + path
                async with session.get(full_url) as resp:
                    print(f"[{resp.status}] {full_url}")
                    text = await resp.text()
                    snippet = text[:150].replace("\n", " ").strip()
                    if "phpMyAdmin" in text or "Welcome" in text or "root@" in text:
                        print(f"    ↳ ⚠️  Contenuto interessante: {snippet[:80]}...")
                        
        except Exception as e:
            print(f"[!] Errore: {e}")
            
            
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Uso: python post_login.py <target> <user> <pass>")
    else:
        asyncio.run(login_and_scan(sys.argv[1], sys.argv[2], sys.argv[3]))
import os
import json
from datetime import datetime


LOG_DIR = "logs" 


def _get_log_file_path() -> str:
    """Restituisce il percorso del file di log basato sulla data odierna UTC."""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    return os.path.join(LOG_DIR, f"{date_str}.json")


def append_log_entry(
    command_name: str,
    user_id: int,
    username: str,
    input_data: str,
    output_data: str
) -> None:
    """
    Aggiunge una nuova entry di log nel file del giorno corrente.
    
    Args:
        command_name: nome del comando che ha generato il log
        user_id: ID Telegram dell’utente
        username: username Telegram (può essere stringa vuota)
        input_data: dati di input forniti dall’utente (es. argomenti comando)
        output_data: output generato dal comando (risultato)
    """
    path = _get_log_file_path()

    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                logs = json.load(f)
        else:
            logs = []
    except (json.JSONDecodeError, IOError):
        logs = []

    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "command": command_name,
        "user_id": user_id,
        "username": username,
        "input": input_data,
        "output": output_data
    }
    logs.append(log_entry)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2, ensure_ascii=False)

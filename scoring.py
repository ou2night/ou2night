import re

WEIGHTED_PATTERNS = [
    (r"\bINFORMATION_SCHEMA\b", 35, "Разведка структуры БД"),
    (r"\bUNION\b",              25, "UNION SELECT"),
    (r"\bEXTRACTVALUE\b",      30, "Error-based инъекция"),
    (r"\bUPDATEXML\b",          30, "Error-based инъекция"),
    (r"\bSLEEP\b",              30, "Time-based инъекция"),
    (r"\bBENCHMARK\b",          30, "Time-based инъекция"),
    (r"\bDROP\b",               40, "DROP таблицы"),
    (r"\bINSERT\b",             20, "INSERT запрос"),
    (r"\bSELECT\b",             20, "SELECT запрос"),
    (r"CONCAT\s*\(",            15, "CONCAT обфускация"),
    (r"CHAR\s*\(",              15, "CHAR обфускация"),
    (r"0x[0-9a-fA-F]+",        20, "Hex-кодировка"),
    (r"/\*.*\*/",               15, "Блочный комментарий"),
    (r"\bOR\b\s*.+=.+",         20, "OR-инъекция"),
    (r"\bAND\b\s*.+=.+",        15, "AND-инъекция"),
    (r"--",                     15, "SQL-комментарий --"),
    (r"#",                      10, "SQL-комментарий #"),
    (r"'",                      10, "Одиночная кавычка"),
]

SUSPICIOUS_AGENTS = [
    "sqlmap", "nikto", "nmap", "curl",
    "python-requests", "wget", "scanner"
]

def calculate_score(value: str, ip: str, user_agent: str, ip_attempts: int):
    score    = 0
    triggered = []

    # Фактор 1 — паттерны SQL (берём первый совпавший — самый специфичный)
    for pattern, weight, label in WEIGHTED_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            score += weight
            triggered.append(f"{label}(+{weight})")
            break

    # Фактор 2 — подозрительный User-Agent
    for agent in SUSPICIOUS_AGENTS:
        if agent in user_agent.lower():
            score += 20
            triggered.append("Подозрительный агент(+20)")
            break

    # Фактор 3 — история IP
    if ip_attempts >= 10:
        score += 30
        triggered.append("Много попыток с IP(+30)")
    elif ip_attempts >= 5:
        score += 15
        triggered.append("Повторные попытки(+15)")
    elif ip_attempts >= 2:
        score += 10
        triggered.append("Повторная попытка(+10)")

    # Фактор 4 — несколько паттернов одновременно
    all_matches = sum(
        1 for pattern, _, _ in WEIGHTED_PATTERNS
        if re.search(pattern, value, re.IGNORECASE)
    )
    if all_matches >= 3:
        score += 15
        triggered.append("Множество паттернов(+15)")

    return score, triggered

def get_decision(score: int):
    if score >= 60:
        return "БАН",         "🔴 КРИТИЧЕСКИЙ", 60
    elif score >= 30:
        return "БЛОКИРОВАТЬ", "🟠 ВЫСОКИЙ",     None
    elif score >= 20:
        return "БЛОКИРОВАТЬ", "🟡 СРЕДНИЙ",      None
    else:
        return "ПРОПУСТИТЬ",  "✅ НИЗКИЙ",       None
import re
import csv
import sqlite3
import threading
import requests
from datetime import datetime, timezone, timedelta
from io import StringIO

TELEGRAM_TOKEN = "8253723736:AAHRPPeSZ6d1678TluQaUQnAbl8oNfSVFxQ"
CHAT_ID        = "1210889666"
DB_PATH        = "/app/security/attacks.db"

SQL_PATTERNS = [
    (r"\bINFORMATION_SCHEMA\b", "Разведка структуры БД"),
    (r"\bUNION\b",              "UNION SELECT (извлечение данных)"),
    (r"\bEXTRACTVALUE\b",      "Error-based инъекция"),
    (r"\bUPDATEXML\b",          "Error-based инъекция"),
    (r"\bSLEEP\b",              "Time-based слепая инъекция"),
    (r"\bBENCHMARK\b",          "Time-based слепая инъекция"),
    (r"\bDROP\b",               "DROP (удаление таблиц)"),
    (r"\bINSERT\b",             "INSERT-запрос"),
    (r"\bSELECT\b",             "SELECT-запрос"),
    (r"CONCAT\s*\(",            "CONCAT() обфускация"),
    (r"CHAR\s*\(",              "CHAR() обфускация"),
    (r"0x[0-9a-fA-F]+",        "Hex-кодировка"),
    (r"/\*.*\*/",               "Блочный комментарий"),
    (r"\bOR\b\s*.+=.+",         "OR-инъекция (OR 1=1)"),
    (r"\bAND\b\s*.+=.+",        "AND-инъекция"),
    (r"--",                     "SQL-комментарий (--)"),
    (r"#",                      "SQL-комментарий (#)"),
    (r"'",                      "Одиночная кавычка (базовый тест)"),
]

# ──────────────────────────────────────────────
# БАЗА ДАННЫХ
# ──────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id    TEXT UNIQUE,
            timestamp   TEXT,
            ip          TEXT,
            field       TEXT,
            payload     TEXT,
            attack_type TEXT,
            threat      TEXT,
            user_agent  TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_attack(event_id, timestamp, ip, field, payload, attack_type, threat, user_agent):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT OR IGNORE INTO attacks
        (event_id, timestamp, ip, field, payload, attack_type, threat, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (event_id, timestamp, ip, field, payload, attack_type, threat, user_agent))
    conn.commit()
    conn.close()

def query_db(sql, params=()):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return rows

# ──────────────────────────────────────────────
# ОПРЕДЕЛЕНИЕ АТАКИ
# ──────────────────────────────────────────────

def detect_attack(value: str):
    for pattern, description in SQL_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return True, description
    return False, ""

def get_threat_level(value: str):
    matches = sum(
        1 for pattern, _ in SQL_PATTERNS
        if re.search(pattern, value, re.IGNORECASE)
    )
    if matches >= 4:
        return "КРИТИЧЕСКИЙ", "🔴"
    elif matches >= 2:
        return "ВЫСОКИЙ", "🟠"
    else:
        return "СРЕДНИЙ", "🟡"

# ──────────────────────────────────────────────
# ОТПРАВКА СООБЩЕНИЙ
# ──────────────────────────────────────────────

def send_message(chat_id, text):
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=5
        )
    except Exception:
        pass

def send_keyboard(chat_id, text, buttons):
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": text,
                "reply_markup": {"inline_keyboard": buttons}
            },
            timeout=5
        )
    except Exception:
        pass

def send_document(chat_id, filename, content, caption=""):
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument",
            data={"chat_id": chat_id, "caption": caption},
            files={"document": (filename, content)},
            timeout=10
        )
    except Exception:
        pass

# ──────────────────────────────────────────────
# УВЕДОМЛЕНИЕ ОБ АТАКЕ
# ──────────────────────────────────────────────

def send_telegram_alert(field: str, payload: str, ip: str, user_agent: str, score: int = 0):
    is_attack, attack_type = detect_attack(payload)
    if not is_attack:
        return

    threat_level, emoji = get_threat_level(payload)
    almaty   = timezone(timedelta(hours=5))
    now      = datetime.now(almaty).strftime("%Y-%m-%d %H:%M:%S")
    event_id = datetime.now(almaty).strftime("%Y%m%d%H%M%S") + f"{abs(hash(payload)) % 1000:03d}"
    safe_pay = (payload[:120]
                .replace("_", " ")
                .replace("*", " ")
                .replace("`", " ")
                .replace("[", " "))

    save_attack(event_id, now, ip, field, payload[:500],
                attack_type, threat_level, user_agent[:200])

    message = (
        f"{emoji} ОБНАРУЖЕНА SQL-ИНЪЕКЦИЯ\n"
        f"──────────────────────────────\n"
        f"ID события: {event_id}\n"
        f"Время: {now}\n"
        f"IP-адрес: {ip}\n"
        f"Поле: {field}\n"
        f"Уровень угрозы: {threat_level}\n"
        f"Тип атаки: {attack_type}\n"
        f"Балл риска IDS: {score}\n"
        f"Payload: {safe_pay}\n"
        f"User-Agent: {user_agent[:80]}\n"
        f"──────────────────────────────\n"
        f"Запрос заблокирован системой защиты"
    )
    send_message(CHAT_ID, message)

# ──────────────────────────────────────────────
# КОМАНДЫ БОТА
# ──────────────────────────────────────────────

def handle_stats(chat_id, period):
    almaty = timezone(timedelta(hours=5))
    now    = datetime.now(almaty)

    if period == "сегодня":
        since = now.strftime("%Y-%m-%d") + " 00:00:00"
        label = "сегодня"
    elif period == "неделя":
        since = (now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
        label = "за последние 7 дней"
    elif period == "месяц":
        since = now.strftime("%Y-%m") + "-01 00:00:00"
        label = "за текущий месяц"
    else:
        send_message(chat_id, "Используй:\n/stats сегодня\n/stats неделя\n/stats месяц")
        return

    rows  = query_db("SELECT * FROM attacks WHERE timestamp >= ?", (since,))
    total = len(rows)

    if total == 0:
        send_message(chat_id, f"За период ({label}) атак не зафиксировано.")
        return

    critical = sum(1 for r in rows if r["threat"] == "КРИТИЧЕСКИЙ")
    high     = sum(1 for r in rows if r["threat"] == "ВЫСОКИЙ")
    medium   = sum(1 for r in rows if r["threat"] == "СРЕДНИЙ")

    types = {}
    for r in rows:
        types[r["attack_type"]] = types.get(r["attack_type"], 0) + 1
    top     = sorted(types.items(), key=lambda x: -x[1])[:3]
    top_str = "\n".join(f"  {t}: {c}" for t, c in top)

    send_message(chat_id, (
        f"Статистика {label}\n"
        f"──────────────────────────────\n"
        f"Всего атак: {total}\n"
        f"🔴 Критических: {critical}\n"
        f"🟠 Высоких: {high}\n"
        f"🟡 Средних: {medium}\n"
        f"──────────────────────────────\n"
        f"Топ типов атак:\n{top_str}"
    ))

def handle_history(chat_id, date_from, date_to):
    try:
        rows = query_db(
            "SELECT * FROM attacks WHERE timestamp >= ? AND timestamp <= ? "
            "ORDER BY timestamp DESC",
            (date_from + " 00:00:00", date_to + " 23:59:59")
        )
        if not rows:
            send_message(chat_id, f"За период {date_from} — {date_to} атак не найдено.")
            return

        lines = [
            f"Атаки за {date_from} — {date_to} (всего: {len(rows)})\n"
            f"──────────────────────────────"
        ]
        for r in rows[:20]:
            lines.append(
                f"[{r['event_id']}] {r['timestamp']} | "
                f"{r['ip']} | {r['threat']} | {r['attack_type']}"
            )
        if len(rows) > 20:
            lines.append(f"...и ещё {len(rows) - 20} записей. Используй /export для полной выгрузки.")
        send_message(chat_id, "\n".join(lines))
    except Exception as e:
        send_message(chat_id, f"Ошибка: {e}\nФормат: /history 09.03.2026 11.03.2026")

def handle_export(chat_id, date_from, date_to):
    try:
        rows = query_db(
            "SELECT * FROM attacks WHERE timestamp >= ? AND timestamp <= ?",
            (date_from + " 00:00:00", date_to + " 23:59:59")
        )
        if not rows:
            send_message(chat_id, f"За период {date_from} — {date_to} данных нет.")
            return

        buf    = StringIO()
        writer = csv.writer(buf)
        writer.writerow(["event_id", "timestamp", "ip", "field",
                         "payload", "attack_type", "threat", "user_agent"])
        for r in rows:
            writer.writerow([r["event_id"], r["timestamp"], r["ip"], r["field"],
                             r["payload"], r["attack_type"], r["threat"], r["user_agent"]])

        filename = f"attacks_{date_from}_{date_to}.csv"
        send_document(chat_id, filename, buf.getvalue().encode("utf-8"),
                      f"Экспорт атак: {date_from} — {date_to}")
    except Exception as e:
        send_message(chat_id, f"Ошибка экспорта: {e}\nФормат: /export 09.03.2026 11.03.2026")

def handle_search_ip(chat_id, ip):
    rows = query_db(
        "SELECT * FROM attacks WHERE ip = ? ORDER BY timestamp DESC", (ip,)
    )
    if not rows:
        send_message(chat_id, f"Атак с IP {ip} не найдено.")
        return

    lines = [f"Атаки с IP {ip} (всего: {len(rows)})\n──────────────────────────────"]
    for r in rows[:15]:
        lines.append(
            f"[{r['event_id']}] {r['timestamp']} | {r['threat']} | {r['attack_type']}"
        )
    if len(rows) > 15:
        lines.append(f"...и ещё {len(rows) - 15} записей.")
    send_message(chat_id, "\n".join(lines))

def handle_attack_detail(chat_id, event_id):
    rows = query_db("SELECT * FROM attacks WHERE event_id = ?", (event_id,))
    if not rows:
        send_message(chat_id, f"Событие {event_id} не найдено.")
        return

    r = rows[0]
    send_message(chat_id, (
        f"Детали события {r['event_id']}\n"
        f"──────────────────────────────\n"
        f"Время: {r['timestamp']}\n"
        f"IP-адрес: {r['ip']}\n"
        f"Поле: {r['field']}\n"
        f"Уровень угрозы: {r['threat']}\n"
        f"Тип атаки: {r['attack_type']}\n"
        f"Payload: {r['payload'][:200]}\n"
        f"User-Agent: {r['user_agent'][:100]}"
    ))

# ──────────────────────────────────────────────
# ОБРАБОТКА КНОПОК
# ──────────────────────────────────────────────

def handle_callback(chat_id, data):
    if data.startswith("stats_"):
        handle_stats(chat_id, data[6:])
    elif data == "hint_history":
        send_message(chat_id,
            "Для получения истории атак напиши:\n"
            "/history 09.03.2026 11.03.2026\n\n"
            "Можно указать любой период.")
    elif data == "hint_export":
        send_message(chat_id,
            "Для экспорта атак в CSV напиши:\n"
            "/export 09.03.2026 11.03.2026\n\n"
            "Файл придёт прямо в этот чат.")
    elif data == "hint_search":
        send_message(chat_id,
            "Для поиска атак по IP напиши:\n"
            "/search ip 172.20.0.1\n\n"
            "Можно указать любой IP-адрес.")
    elif data == "hint_attack":
        send_message(chat_id,
            "Для просмотра деталей события напиши:\n"
            "/attack 20260309143022001\n\n"
            "ID события указан в каждом уведомлении об атаке.")

# ──────────────────────────────────────────────
# ОБРАБОТКА КОМАНД
# ──────────────────────────────────────────────

def handle_commands(chat_id, text):
    text = text.strip()

    if text in ("/start", "/help"):
        send_keyboard(chat_id,
            "Панель управления ACorp Security Bot\nВыбери действие:",
            [
                [
                    {"text": "📊 Сегодня", "callback_data": "stats_сегодня"},
                    {"text": "📅 Неделя",  "callback_data": "stats_неделя"},
                    {"text": "🗓 Месяц",   "callback_data": "stats_месяц"},
                ],
                [
                    {"text": "📋 История атак",   "callback_data": "hint_history"},
                    {"text": "📤 Экспорт CSV",    "callback_data": "hint_export"},
                ],
                [
                    {"text": "🔍 Поиск по IP",    "callback_data": "hint_search"},
                    {"text": "🔎 Детали события", "callback_data": "hint_attack"},
                ],
            ]
        )
    elif text.startswith("/stats "):
        handle_stats(chat_id, text[7:].strip().lower())
    elif text.startswith("/history "):
        parts = text.split()
        if len(parts) == 3:
            try:
                d1 = "-".join(reversed(parts[1].split(".")))
                d2 = "-".join(reversed(parts[2].split(".")))
                handle_history(chat_id, d1, d2)
            except Exception:
                send_message(chat_id, "Формат: /history 09.03.2026 11.03.2026")
        else:
            send_message(chat_id, "Формат: /history 09.03.2026 11.03.2026")

    elif text.startswith("/export "):
        parts = text.split()
        if len(parts) == 3:
            try:
                d1 = "-".join(reversed(parts[1].split(".")))
                d2 = "-".join(reversed(parts[2].split(".")))
                handle_export(chat_id, d1, d2)
            except Exception:
                send_message(chat_id, "Формат: /export 09.03.2026 11.03.2026")
        else:
            send_message(chat_id, "Формат: /export 09.03.2026 11.03.2026")
    elif text.startswith("/search ip "):
        ip = text[11:].strip()
        if ip:
            handle_search_ip(chat_id, ip)
        else:
            send_message(chat_id, "Формат: /search ip 172.20.0.1")

    elif text.startswith("/attack "):
        event_id = text[8:].strip()
        if event_id:
            handle_attack_detail(chat_id, event_id)
        else:
            send_message(chat_id, "Формат: /attack 20260309143022001")

# ──────────────────────────────────────────────
# POLLING
# ──────────────────────────────────────────────

def poll_bot():
    offset = None
    while True:
        try:
            params = {"timeout": 30}
            if offset:
                params["offset"] = offset
            resp = requests.get(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates",
                params=params, timeout=35
            )
            data = resp.json()
            for update in data.get("result", []):
                offset = update["update_id"] + 1

                if "message" in update:
                    msg = update["message"]
                    txt = msg.get("text", "")
                    cid = str(msg.get("chat", {}).get("id"))
                    if txt and cid:
                        handle_commands(cid, txt)

                elif "callback_query" in update:
                    cb      = update["callback_query"]
                    cid     = str(cb.get("message", {}).get("chat", {}).get("id"))
                    data_cb = cb.get("data", "")
                    try:
                        requests.post(
                            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/answerCallbackQuery",
                            json={"callback_query_id": cb["id"]},
                            timeout=5
                        )
                    except Exception:
                        pass
                    if cid and data_cb:
                        handle_callback(cid, data_cb)
        except Exception:
            pass

# ──────────────────────────────────────────────
# ИНИЦИАЛИЗАЦИЯ
# ──────────────────────────────────────────────

init_db()
threading.Thread(target=poll_bot, daemon=True).start()
from flask import request
from functools import wraps
from .scoring import calculate_score, get_decision
from .storage import (
    log_request, get_ip_attempts,
    increment_ip_attempts, ban_ip, is_ip_banned
)

def ids_check(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip         = request.remote_addr
        user_agent = request.headers.get("User-Agent", "")
        method     = request.method
        path       = request.path

        # Проверка бана
        if is_ip_banned(ip):
            log_request(ip, method, path, "BANNED_IP", 999, "БАН", "IP в бан-листе")
            return "Доступ запрещён. Обратитесь к администратору.", 403

        # Собираем все входные данные
        values = []
        if request.form:
            values.extend(request.form.values())
        if request.args:
            values.extend(request.args.values())

        for value in values:
            if not value:
                continue

            ip_data  = get_ip_attempts(ip)
            attempts = ip_data["attempts"] if ip_data else 0

            score, triggered = calculate_score(value, ip, user_agent, attempts)
            decision, threat, ban_minutes = get_decision(score)
            factors = ", ".join(triggered)

            if decision in ("БЛОКИРОВАТЬ", "БАН"):
                log_request(ip, method, path, value, score, decision, factors)
                increment_ip_attempts(ip)

                if ban_minutes:
                    ban_ip(ip, ban_minutes)

                try:
                    from security.alert_bot import send_telegram_alert
                    send_telegram_alert(
                        field=path,
                        payload=value,
                        ip=ip,
                        user_agent=user_agent,
                        score=score
                    )
                except Exception:
                    pass

                return "Запрос заблокирован системой безопасности IDS.", 403

        return f(*args, **kwargs)
    return decorated
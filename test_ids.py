import sys
sys.path.insert(0, '/app')
from ids.scoring import calculate_score, get_decision

# ══ НАБОР 1 — АТАКИ (20 штук) ══
attacks = [
    ("admin'--",                                           "Auth bypass"),
    ("' OR 1=1--",                                         "OR-инъекция"),
    ("' UNION SELECT 1,2,3--",                             "UNION-based"),
    ("' AND SLEEP(3)--",                                   "Time-based"),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",     "Error-based"),
    ("' UNION SELECT table_name FROM information_schema.tables--", "Разведка БД"),
    ("'; DROP TABLE users--",                              "DROP"),
    ("' OR 0x61646d696e--",                                "Hex-кодировка"),
    ("' OR CHAR(49)=CHAR(49)--",                           "CHAR обфускация"),
    ("' UNION SELECT CONCAT(username,password) FROM users--", "CONCAT"),
    ("admin'#",                                            "Комментарий #"),
    ("' AND BENCHMARK(1000000,MD5(1))--",                  "BENCHMARK"),
    ("' OR '1'='1",                                        "OR-строка"),
    ("1 OR 1=1",                                           "Числовая инъекция"),
    ("' AND 1=1--",                                        "AND-инъекция"),
    ("admin'/**/--",                                       "Блочный комментарий"),
    ("' UNION SELECT NULL--",                              "UNION NULL"),
    ("'; INSERT INTO users VALUES('x','y','admin')--",     "INSERT"),
    ("' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",      "UPDATEXML"),
    ("' OR SLEEP(5)#",                                     "Time-based #"),
]

# ══ НАБОР 2 — ЛЕГИТИМНЫЕ (20 штук) ══
legitimate = [
    ("admin",               "Обычный логин"),
    ("john.doe",            "Логин с точкой"),
    ("O'Brien",             "Имя с кавычкой"),
    ("user@mail.com",       "Email"),
    ("password123",         "Пароль"),
    ("Иванов",              "Кириллица"),
    ("test_user",           "Логин с подчёркиванием"),
    ("Mary-Jane",           "Имя с дефисом"),
    ("support#team",        "Символ решётки"),
    ("hello--world",        "Двойной дефис"),
    ("user.name",           "Точка в логине"),
    ("Алтынай",             "Имя на казахском"),
    ("john_doe_123",        "Логин цифры"),
    ("user2026",            "Логин с годом"),
    ("Admin",               "Заглавные буквы"),
    ("firstname.lastname",  "Имя фамилия"),
    ("test@test.com",       "Email тест"),
    ("qwerty123",           "Простой пароль"),
    ("Bekova_A",            "Логин казахский"),
    ("manager01",           "Логин менеджер"),
]

print("=" * 65)
print("ТЕСТИРОВАНИЕ МОДУЛЯ IDS — СКОРИНГОВАЯ МОДЕЛЬ")
print("=" * 65)

TP = FP = FN = TN = 0

print("\n── АТАКИ ──────────────────────────────────────────────────")
print(f"{'№':<3} {'Статус':<22} {'Балл':<6} {'Тип атаки':<30}")
print("-" * 65)

for i, (payload, attack_type) in enumerate(attacks, 1):
    score, factors = calculate_score(payload, "1.2.3.4", "Mozilla/5.0", 0)
    decision, threat, _ = get_decision(score)
    blocked = decision in ("БЛОКИРОВАТЬ", "БАН")
    if blocked:
        TP += 1
        status = "✅ ЗАБЛОКИРОВАН"
    else:
        FN += 1
        status = "❌ ПРОПУЩЕН"
    print(f"{i:<3} {status:<22} {score:<6} {attack_type:<30}")

print("\n── ЛЕГИТИМНЫЕ ЗАПРОСЫ ──────────────────────────────────────")
print(f"{'№':<3} {'Статус':<26} {'Балл':<6} {'Описание':<30}")
print("-" * 65)

for i, (payload, description) in enumerate(legitimate, 1):
    score, factors = calculate_score(payload, "1.2.3.4", "Mozilla/5.0", 0)
    decision, threat, _ = get_decision(score)
    blocked = decision in ("БЛОКИРОВАТЬ", "БАН")
    if not blocked:
        TN += 1
        status = "✅ ПРОПУЩЕН ВЕРНО"
    else:
        FP += 1
        status = "❌ ЛОЖНОЕ СРАБАТЫВАНИЕ"
    print(f"{i:<3} {status:<26} {score:<6} {description:<30}")

# ══ МЕТРИКИ ══
precision = TP / (TP + FP) if (TP + FP) > 0 else 0
recall    = TP / (TP + FN) if (TP + FN) > 0 else 0
f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
accuracy  = (TP + TN) / (TP + TN + FP + FN)

print("\n" + "=" * 65)
print("РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ")
print("=" * 65)
print(f"TP — атаки заблокированы верно:       {TP:>3} из 20")
print(f"FP — легитимные заблокированы:         {FP:>3} из 20")
print(f"FN — атаки пропущены:                  {FN:>3} из 20")
print(f"TN — легитимные пропущены верно:       {TN:>3} из 20")
print("-" * 65)
print(f"Точность    (Precision): {precision:.2f}")
print(f"Полнота     (Recall):    {recall:.2f}")
print(f"F1-мера:                 {f1:.2f}")
print(f"Accuracy:                {accuracy:.2f}")
print("=" * 65)

if f1 >= 0.90:
    print("Оценка: ОТЛИЧНО — система работает эффективно")
elif f1 >= 0.75:
    print("Оценка: ХОРОШО — система работает приемлемо")
else:
    print("Оценка: ТРЕБУЕТ ДОРАБОТКИ")
print("=" * 65)
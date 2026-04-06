from ids.middleware import ids_check
from ids.storage import init_ids_db
import sqlite3 as sqlite_ids
import os
import re
import MySQLdb
from security.alert_bot import detect_attack, send_telegram_alert
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, g
)

app = Flask(__name__)
init_ids_db()
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

DB_CONFIG = {
    "host":        os.environ.get("DB_HOST",     "localhost"),
    "port":        int(os.environ.get("DB_PORT", 3306)),
    "db":          os.environ.get("DB_NAME",     "acorp"),
    "user":        os.environ.get("DB_USER",     "acorp_user"),
    "passwd":      os.environ.get("DB_PASSWORD", "acorp_pass"),
    "charset":     "utf8mb4",
    "use_unicode": True,
}


def get_db():
    if "db" not in g:
        g.db = MySQLdb.connect(**DB_CONFIG)
        g.db.autocommit(True)
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, params=None, fetch="all"):
    cursor = get_db().cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(sql, params or ())
    if fetch == "one":
        return cursor.fetchone()
    return cursor.fetchall()


def validate_username(value):                                 #валидация
    if not value or len(value) > 80:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_@.\-]+$', value))


def validate_id(value):
    if not value:
        return False
    return bool(re.match(r'^\d+$', str(value)))


def sanitize_search(value):
    if not value:
        return ""
    value = value.strip()[:100]
    value = re.sub(r"['\";\\<>]", "", value)
    return value



@app.route("/")
def index():
    stats = {
        "employees":   query("SELECT COUNT(*) AS n FROM employees",   fetch="one")["n"],
        "departments": query("SELECT COUNT(*) AS n FROM departments", fetch="one")["n"],
    }
    return render_template("index.html", stats=stats)


@app.route("/login", methods=["GET", "POST"])
@ids_check
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        ip = request.remote_addr
        user_agent = request.headers.get("User-Agent", "unknown")
        
        if not validate_username(username):
            error = "Invalid credentials. Please try again."
            return render_template("login.html", error=error)

        escaped_user = get_db().escape_string(username).decode("utf-8")
        escaped_pass = get_db().escape_string(password).decode("utf-8")        #экранирование

        try:
            user = query(
                "SELECT * FROM users WHERE username = %s AND password = %s",    #параметризация
                (escaped_user, escaped_pass),
                fetch="one"
            )
        except Exception:
            error = "Invalid credentials. Please try again."
            return render_template("login.html", error=error)

        if user:
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid credentials. Please try again."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    recent = query(
        "SELECT e.full_name, e.position, d.name AS dept "
        "FROM employees e JOIN departments d ON e.department_id = d.id "
        "ORDER BY e.hire_date DESC LIMIT 5"
    )
    return render_template("dashboard.html", recent=recent)


@app.route("/employees")
def employees():
    if "user_id" not in session:
        return redirect(url_for("login"))

    search = sanitize_search(request.args.get("search", ""))
    error  = None
    rows   = []

    try:
        if search:
            like_val = "%" + search + "%"
            rows = query(
                "SELECT e.*, d.name AS dept_name "
                "FROM employees e "
                "LEFT JOIN departments d ON e.department_id = d.id "
                "WHERE e.full_name LIKE %s OR e.position LIKE %s",
                (like_val, like_val)
            )
        else:
            rows = query(
                "SELECT e.*, d.name AS dept_name "
                "FROM employees e "
                "LEFT JOIN departments d ON e.department_id = d.id "
                "ORDER BY e.department_id, e.full_name"
            )
    except Exception:
        error = "An error occurred. Please try again."

    return render_template("employees.html", rows=rows, search=search, error=error)


@app.route("/departments")
def departments():
    if "user_id" not in session:
        return redirect(url_for("login"))

    dept_id = request.args.get("id", "")
    error   = None
    dept    = None
    members = []

    if dept_id:
        if not validate_id(dept_id):
            error = "Invalid department ID."
        else:
            try:
                dept = query(
                    "SELECT * FROM departments WHERE id = %s",
                    (int(dept_id),),
                    fetch="one"
                )
                if dept:
                    members = query(
                        "SELECT full_name, position, email "
                        "FROM employees WHERE department_id = %s",
                        (int(dept_id),)
                    )
            except Exception:
                error = "An error occurred. Please try again."
                dept  = None

    all_depts = query("SELECT * FROM departments ORDER BY name")
    return render_template(
        "departments.html",
        all_depts=all_depts,
        dept=dept,
        members=members,
        dept_id=dept_id,
        error=error,
    )
@app.route("/admin/security")
def security_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    IDS_DB = "/app/ids/ids.db"

    def ids_query(sql, params=()):
        conn = sqlite_ids.connect(IDS_DB)
        conn.row_factory = sqlite_ids.Row
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return rows

    # Метрики
    total      = ids_query("SELECT COUNT(*) as n FROM ids_log")[0]["n"]
    today_str  = __import__('datetime').date.today().isoformat()
    today      = ids_query("SELECT COUNT(*) as n FROM ids_log WHERE timestamp LIKE ?", (today_str + "%",))[0]["n"]
    unique_ips = ids_query("SELECT COUNT(DISTINCT ip) as n FROM ids_log")[0]["n"]
    banned     = ids_query("SELECT COUNT(*) as n FROM ip_history WHERE banned_until > datetime('now','localtime')")[0]["n"]

    # График по дням
    daily_data = ids_query("""
        SELECT DATE(timestamp) as day, COUNT(*) as cnt
        FROM ids_log
        WHERE timestamp >= datetime('now','localtime','-30 days')
        GROUP BY DATE(timestamp)
        ORDER BY day
    """)

    # Топ IP
    top_ips = ids_query("""
        SELECT ip, COUNT(*) as cnt
        FROM ids_log
        GROUP BY ip
        ORDER BY cnt DESC
        LIMIT 5
    """)

    # Типы атак (используем factors вместо attack_type)
    attack_types = ids_query("""
        SELECT factors as attack_type, COUNT(*) as cnt
        FROM ids_log
        GROUP BY factors
        ORDER BY cnt DESC
        LIMIT 6
    """)

    # Уровни угроз (используем decision вместо threat)
    threat_levels = ids_query("""
        SELECT decision as threat, COUNT(*) as cnt
        FROM ids_log
        GROUP BY decision
        ORDER BY cnt DESC
    """)

    # Последние 10 событий
    recent_attacks = ids_query("""
        SELECT *, factors as attack_type, decision as threat, score
        FROM ids_log
        ORDER BY timestamp DESC
        LIMIT 10
    """)

    from datetime import date
    return render_template("security_dashboard.html",
        stats={"total": total, "today": today, "unique_ips": unique_ips, "banned": banned},
        today_date=date.today().strftime("%d.%m.%Y"),
        daily_data=daily_data,
        top_ips=top_ips,
        attack_types=attack_types,
        threat_levels=threat_levels,
        recent_attacks=recent_attacks,
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)

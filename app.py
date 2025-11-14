# app.py
from flask import Flask, request, jsonify, render_template, send_from_directory, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import os
import random
import re

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'app.db')

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'  # used for non-API redirects


# -------------------------
# Models
# -------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    codeword = db.Column(db.String(256), nullable=False)  # кодовое слово для восстановления

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

    def get_display_name(self):
        return f"{self.first_name} {self.last_name}"


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_user_task = db.Column(db.Boolean, default=False)


class UserTaskFlag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    favorite = db.Column(db.Boolean, default=False)
    solved = db.Column(db.Boolean, default=False)
    solved_at = db.Column(db.DateTime, nullable=True)

    __table_args__ = (db.UniqueConstraint('user_id', 'task_id', name='_user_task_uc'),)


class CalendarEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    count = db.Column(db.Integer, default=0)

    __table_args__ = (db.UniqueConstraint('user_id', 'date', name='_user_date_uc'),)


# -------------------------
# Login manager
# -------------------------
@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None


# Ensure API unauthorized requests return JSON (not redirect).
@login_manager.unauthorized_handler
def unauthorized_callback():
    # If it's an API route, return JSON 401, otherwise redirect to index
    if request.path.startswith('/api/'):
        return jsonify({'error': 'not_authenticated', 'message': 'Требуется авторизация'}), 401
    return redirect(url_for('index'))


# -------------------------
# Utility helpers
# -------------------------
def task_to_dict(task, user=None):
    """Serialize task, include flag fields if user provided."""
    d = {
        'id': task.id,
        'title': task.title,
        'content': task.content,
        'is_user_task': bool(task.is_user_task),
        'created_at': task.created_at.isoformat() if task.created_at else None,
        'author_id': task.author_id
    }
    if user and user.is_authenticated:
        f = UserTaskFlag.query.filter_by(user_id=user.id, task_id=task.id).first()
        d['favorite'] = bool(f and f.favorite)
        d['solved'] = bool(f and f.solved)
    else:
        d['favorite'] = False
        d['solved'] = False
    return d


# -------------------------
# Validation helpers
# -------------------------
# Name validation: Russian letters, starts with uppercase, then zero or more lowercase letters
# Accept "Ё" and "ё" as well.
NAME_RE = re.compile(r'^[А-ЯЁ][а-яё]*$')

def validate_name_field(value):
    if not value:
        return False
    # require at least 1 character (as requested)
    if len(value) < 1:
        return False
    # must match Russian letters pattern: starts uppercase, rest lowercase (rest may be empty)
    return bool(NAME_RE.match(value))


# Email validation (simple, typical)
EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$')

def validate_email(value):
    if not value:
        return False
    return bool(EMAIL_RE.match(value))


# Password validation
# Allowed punctuation list (as per spec) - **no spaces**
# Allowed symbols: ~ ! ? @ # $ % ^ & * _ - + ( ) [ ] { } > < / \ | " ' . , : ;
ALLOWED_PUNCT = r"""~!?@#$%^&*_+-()[]{}></\|"'.,:;"""  # note: no spaces

def validate_password(password):
    # returns (True, None) if valid, else (False, message)
    if not isinstance(password, str):
        return False, "Пароль должен быть строкой"
    if len(password) < 8:
        return False, "Пароль должен содержать не менее 8 символов"
    if len(password) > 128:
        return False, "Пароль не должен превышать 128 символов"
    if any(ch.isspace() for ch in password):
        return False, "Пароль не должен содержать пробелов"
    # at least one digit (arabic digits)
    if not re.search(r'[0-9]', password):
        return False, "Пароль должен содержать как минимум одну цифру"
    # at least one uppercase (Latin or Cyrillic)
    if not re.search(r'[A-ZА-ЯЁ]', password):
        return False, "Пароль должен содержать как минимум одну заглавную букву"
    # at least one lowercase (Latin or Cyrillic)
    if not re.search(r'[a-zа-яё]', password):
        return False, "Пароль должен содержать как минимум одну строчную букву"
    # allowed characters: Latin, Cyrillic, digits, and listed punctuation (no spaces)
    allowed_chars = "A-Za-zА-Яа-яЁё0-9" + re.escape(ALLOWED_PUNCT)
    pattern = re.compile(r'^[' + allowed_chars + r']+$')
    if not pattern.match(password):
        return False, (
            'Пароль содержит недопустимые символы. Допустимы буквы (латиница/кириллица), '
            'цифры 0-9 и символы: ' + ALLOWED_PUNCT
        )
    # all checks passed
    return True, None


# -------------------------
# Routes: serve frontend
# -------------------------
@app.route('/')
def index():
    # serve main frontend file from templates/frontend.html
    return render_template('frontend.html')


# (optional) static files if you keep assets under static/
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)


# -------------------------
# API Endpoints
# -------------------------

# Registration
@app.route('/api/register/', methods=['POST'])
def api_register():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    password2 = data.get('password2') or ''
    first_name = (data.get('first_name') or '').strip()
    last_name = (data.get('last_name') or '').strip()
    codeword = (data.get('codeword') or '').strip()

    if not (email and password and password2 and first_name and last_name and codeword):
        return jsonify({'error': 'fill_all', 'message': 'Заполните все поля'}), 400

    # Name checks (now minimum 1 letter, must start uppercase, others lowercase)
    if not validate_name_field(first_name):
        return jsonify({'error': 'first_name_invalid', 'message': 'Имя должно состоять из русских букв и начинаться с заглавной буквы (минимум 1 буква)'}), 400
    if not validate_name_field(last_name):
        return jsonify({'error': 'last_name_invalid', 'message': 'Фамилия должна состоять из русских букв и начинаться с заглавной буквы (минимум 1 буква)'}), 400

    # Email
    if not validate_email(email):
        return jsonify({'error': 'email_invalid', 'message': 'Неверный формат электронной почты'}), 400

    # Password match
    if password != password2:
        return jsonify({'error': 'mismatch', 'message': 'Пароли не совпадают'}), 400

    # Password validation
    ok, msg = validate_password(password)
    if not ok:
        return jsonify({'error': 'password_invalid', 'message': msg}), 400

    # Already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'exists', 'message': 'Пользователь с таким email уже существует'}), 400

    user = User(email=email, first_name=first_name, last_name=last_name, codeword=codeword)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    login_user(user)
    return jsonify({'ok': True, 'user_id': user.id, 'email': user.email, 'first_name': user.first_name, 'last_name': user.last_name})


# Login
@app.route('/api/login/', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    if not (email and password):
        return jsonify({'error': 'fill_all', 'message': 'Заполните все поля'}), 400
    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'invalid', 'message': 'Неверная почта или пароль'}), 400
    login_user(user)
    return jsonify({'ok': True, 'user_id': user.id, 'email': user.email, 'first_name': user.first_name, 'last_name': user.last_name})


# Logout
@app.route('/api/logout/', methods=['POST'])
def api_logout():
    logout_user()
    return jsonify({'ok': True})


# Password recovery (verify codeword + change)
@app.route('/api/recover/verify/', methods=['POST'])
def api_recover_verify():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    codeword = (data.get('codeword') or '').strip()
    new_password = data.get('new_password') or ''
    if not (email and codeword and new_password):
        return jsonify({'error': 'fill_all', 'message': 'Заполните все поля'}), 400
    user = User.query.filter_by(email=email).first()
    if not user or user.codeword != codeword:
        return jsonify({'error': 'invalid_code', 'message': 'Неверная почта или кодовое слово'}), 400
    ok, msg = validate_password(new_password)
    if not ok:
        return jsonify({'error': 'password_invalid', 'message': msg}), 400
    user.set_password(new_password)
    db.session.commit()
    return jsonify({'ok': True})


# Get all tasks (accessible without auth)
@app.route('/api/tasks/', methods=['GET', 'POST'])
def api_tasks():
    if request.method == 'GET':
        user = current_user if current_user.is_authenticated else None
        # Show only global tasks to unauthenticated users.
        if not user:
            tasks = Task.query.filter_by(is_user_task=False).order_by(Task.id.desc()).all()
        else:
            # show global tasks and user's own tasks
            tasks = Task.query.filter(
                (Task.is_user_task == False) | ((Task.is_user_task == True) & (Task.author_id == user.id))
            ).order_by(Task.id.desc()).all()
        return jsonify({'tasks': [task_to_dict(t, user) for t in tasks]})
    else:
        # create task (auth required)
        if not current_user.is_authenticated:
            return jsonify({'error': 'not_authenticated', 'message': 'Требуется авторизация'}), 401
        data = request.get_json() or {}
        title = (data.get('title') or '').strip()
        content = (data.get('content') or '').strip()
        if not (title and content):
            return jsonify({'error': 'fill_all', 'message': 'Заполните поля'}), 400
        t = Task(title=title, content=content, author_id=current_user.id, is_user_task=True)
        db.session.add(t)
        db.session.commit()
        return jsonify({'ok': True, 'task_id': t.id})


# Get single task (full content)
@app.route('/api/task/<int:task_id>/', methods=['GET'])
def api_task_get(task_id):
    t = Task.query.get(task_id)
    if not t:
        return jsonify({'error': 'no_task', 'message': 'Задача не найдена'}), 404
    # If this is a user-specific task, ensure only owner can access it
    if t.is_user_task:
        if not current_user.is_authenticated or current_user.id != t.author_id:
            # treat as not found for outsiders
            return jsonify({'error': 'no_task', 'message': 'Задача не найдена'}), 404
    user = current_user if current_user.is_authenticated else None
    return jsonify({'task': task_to_dict(t, user)})


# Random task for logged in user (exclude solved)
@app.route('/api/task/random/', methods=['GET'])
@login_required
def api_task_random():
    # tasks available to the user: global tasks + tasks authored by user
    solved_ids = [f.task_id for f in UserTaskFlag.query.filter_by(user_id=current_user.id, solved=True).all()]
    q = Task.query.filter(
        (Task.is_user_task == False) | ((Task.is_user_task == True) & (Task.author_id == current_user.id))
    )
    if solved_ids:
        q = q.filter(~Task.id.in_(solved_ids))
    t = q.order_by(db.func.random()).first()
    if not t:
        return jsonify({'error': 'no_tasks', 'message': 'Нет доступных задач'}), 404
    return jsonify({'task': task_to_dict(t, current_user)})


# Toggle favorite
@app.route('/api/task/<int:task_id>/favorite/', methods=['POST'])
@login_required
def api_task_favorite(task_id):
    t = Task.query.get(task_id)
    if not t:
        return jsonify({'error': 'no_task', 'message': 'Задача не найдена'}), 404
    # Ensure user can favorite only tasks visible to them
    if t.is_user_task and t.author_id != current_user.id:
        return jsonify({'error': 'no_task', 'message': 'Задача не найдена'}), 404
    f = UserTaskFlag.query.filter_by(user_id=current_user.id, task_id=task_id).first()
    if not f:
        f = UserTaskFlag(user_id=current_user.id, task_id=task_id, favorite=True)
        db.session.add(f)
    else:
        # toggle favorite (frontend uses this behaviour)
        f.favorite = not f.favorite
    db.session.commit()
    return jsonify({'ok': True, 'favorite': bool(f.favorite)})


# Mark solved
@app.route('/api/task/<int:task_id>/solve/', methods=['POST'])
@login_required
def api_task_solve(task_id):
    t = Task.query.get(task_id)
    if not t:
        return jsonify({'error': 'no_task', 'message': 'Задача не найдена'}), 404
    # ensure visibility
    if t.is_user_task and t.author_id != current_user.id:
        return jsonify({'error': 'no_task', 'message': 'Задача не найдена'}), 404
    f = UserTaskFlag.query.filter_by(user_id=current_user.id, task_id=task_id).first()
    if not f:
        f = UserTaskFlag(user_id=current_user.id, task_id=task_id, solved=True, solved_at=datetime.utcnow())
        db.session.add(f)
    else:
        # mark solved (idempotent: always set solved=True and update timestamp)
        f.solved = True
        f.solved_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'ok': True})


# Favorites list
@app.route('/api/favorites/', methods=['GET'])
@login_required
def api_favorites():
    # Only return favorites for authenticated user
    flags = UserTaskFlag.query.filter_by(user_id=current_user.id, favorite=True).all()
    res = []
    for f in flags:
        t = Task.query.get(f.task_id)
        if t:
            # ensure visibility (should always hold, but double-check)
            if t.is_user_task and t.author_id != current_user.id:
                continue
            res.append({'id': t.id, 'title': t.title, 'content': t.content, 'solved': bool(f.solved)})
    return jsonify({'tasks': res})


# Solved list (archive)
@app.route('/api/solved/', methods=['GET'])
@login_required
def api_solved():
    flags = UserTaskFlag.query.filter_by(user_id=current_user.id, solved=True).order_by(UserTaskFlag.solved_at.desc()).all()
    res = []
    for f in flags:
        t = Task.query.get(f.task_id)
        if t:
            if t.is_user_task and t.author_id != current_user.id:
                continue
            res.append({'id': t.id, 'title': t.title, 'content': t.content, 'solved_at': f.solved_at.isoformat() if f.solved_at else None})
    return jsonify({'tasks': res})


# Calendar (get user's calendar)
@app.route('/api/calendar/', methods=['GET'])
def api_calendar():
    if not current_user.is_authenticated:
        # return empty dictionary for unauthenticated users (frontend expects {})
        return jsonify({'days': {}})
    entries = CalendarEntry.query.filter_by(user_id=current_user.id).all()
    data = {e.date.isoformat(): e.count for e in entries}
    return jsonify({'days': data})


# Calendar day set
@app.route('/api/calendar/day/', methods=['POST'])
@login_required
def api_calendar_day():
    data = request.get_json() or {}
    date_str = data.get('date')
    try:
        count = int(data.get('count') or 0)
    except Exception:
        return jsonify({'error': 'invalid_count', 'message': 'Неверное количество'}), 400
    if not date_str:
        return jsonify({'error': 'no_date', 'message': 'Отсутствует дата'}), 400
    try:
        d = date.fromisoformat(date_str)
    except Exception:
        return jsonify({'error': 'invalid_date', 'message': 'Неверный формат даты'}), 400
    entry = CalendarEntry.query.filter_by(user_id=current_user.id, date=d).first()
    if entry:
        entry.count = count
    else:
        entry = CalendarEntry(user_id=current_user.id, date=d, count=count)
        db.session.add(entry)
    db.session.commit()
    return jsonify({'ok': True})


# User profile (simple)
@app.route('/api/profile/', methods=['GET'])
@login_required
def api_profile():
    u = current_user
    return jsonify({'email': u.email, 'first_name': u.first_name, 'last_name': u.last_name, 'user_id': u.id})


# -------------------------
# Admin/dev helpers: DB init + seed
# -------------------------
def seed_tasks():
    if Task.query.count() > 0:
        return
    sample = [
        ("Тип 5 — Контрольные биты и число R", "На вход подаётся натуральное число 𝑁 N. Сначала записывают его в двоичном виде. Затем к этой двоичной строке справа поочерёдно приписывают два контрольных бита так: сначала дописывают остаток от деления суммы всех битов текущей записи на 2, а затем повторяют ту же операцию ещё раз над уже расширенной записью. Полученная двоичная последовательность (она длиннее исходной на два разряда) рассматривается как двоичное представление некоторого числа 𝑅 R. Найдите наименьшее возможное значение 𝑅 R (в десятичной системе), превышающее 43, которое может получиться таким образом."),
        ("Тип 11 — Хранение паролей", "В системе каждому пользователю дают пароль из 15 символов, каждый символ выбирается из набора из 12 различных знаков: A, B, C, D, E, F, G, H, K, L, M, N. Для кодирования символов применяют наименьшее целое число бит, достаточное для однозначного представления всех 12 символов (все символы кодируются одинаково). В базе для каждого пользователя резервируется одинаковое и минимально возможное целое число байт для хранения самого пароля (то есть битовая длина пароля округляется вверх до целого числа байт). Кроме пароля для каждого пользователя хранят и дополнительные данные, для которых выделяется одинаковое целое количество байт на одного пользователя. Всего для сведения о 20 пользователях потребовалось 400 байт. Определите, сколько байт отведено под дополнительные сведения для одного пользователя. В ответе укажите только целое число байт."),
        ("Тип 9 — Строки электронной таблицы", "В каждой строке электронной таблицы записаны шесть натуральных чисел. Найдите количество тех строк, в которых все шесть чисел попарно различны, и при этом среднее арифметическое максимального и минимального элементов строки больше, чем среднее арифметическое оставшихся четырёх чисел. В ответе укажите число строк, удовлетворяющих этим требованиям."),
        ("Тип 8 — Слова из букв {З, И, М, А}", "Вася пишет последовательности длины 5, используя только буквы {З, И, М, А}. В каждом таком слове должно быть ровно одна гласная буква (в данном наборе гласные — И и А), и эта гласная встречается ровно один раз. Допустимые согласные (З и М) могут повторяться сколько угодно раз или вообще не появляться. Под «словом» понимается любая допустимая последовательность символов указанной длины. Сколько различных слов может получить Вася? (Ответ — целое число.)")
    ]
    for title, content in sample:
        t = Task(title=title, content=content)
        db.session.add(t)
    db.session.commit()


if __name__ == '__main__':
    # Создаём таблицы и заполняем начальными задачами внутри контекста приложения
    with app.app_context():
        db.create_all()
        try:
            seed_tasks()
        except Exception as e:
            # на случай, если seed уже запускался или что-то пошло не так — логируем, но не падаем
            print("Seed error (можно игнорировать при повторных запусках):", e)

    # Запускаем dev-сервер
    app.run(host='127.0.0.1', port=5000, debug=True)

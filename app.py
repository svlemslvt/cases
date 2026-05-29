import json
import os
import secrets
import time
import uuid
import hashlib
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()  # загружаем переменные окружения из .env

app = Flask(__name__)

#  Исправление 1: секретный ключ из окружения, иначе генерируем случайный 
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    app.secret_key = secrets.token_hex(32)
    print("WARNING: SECRET_KEY не задан, сгенерирован временный. Сохраните его в .env")
app.permanent_session_lifetime = timedelta(days=1)  # Исправление: уменьшен срок сессии

# Исправление 2: шифрование карточных данных 
encryption_key = os.environ.get('ENCRYPTION_KEY')
if not encryption_key:
    encryption_key = Fernet.generate_key().decode()
    print("WARNING: ENCRYPTION_KEY не задан, сгенерирован временный. Сохраните в .env")
fernet = Fernet(encryption_key.encode())

def encrypt_data(data: str) -> str:
    if not data:
        return ""
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(data: str) -> str:
    if not data:
        return ""
    try:
        return fernet.decrypt(data.encode()).decode()
    except:
        return "*** Ошибка шифрования ***"

# ---------- Конфигурация ----------
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp3', 'wav', 'ogg', 'webm'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DATA_FILE = 'data.json'

#  Исправление 3: rate limiting (простой словарь) 
rate_limit_storage = {}

def rate_limit(limit_per_sec=1, key_prefix=''):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # Используем IP + имя функции + возможно username
            client_ip = request.remote_addr
            user = session.get('username', 'anon')
            key = f"{key_prefix}:{client_ip}:{user}:{f.__name__}"
            now = time.time()
            if key in rate_limit_storage:
                if now - rate_limit_storage[key] < limit_per_sec:
                    return jsonify({'success': False, 'message': 'Слишком много запросов'}), 429
            rate_limit_storage[key] = now
            return f(*args, **kwargs)
        return decorated
    return decorator

# ---------- Вспомогательные функции ----------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_user_id():
    return secrets.token_hex(12)

# Исправление 4: улучшенная генерация карты (криптостойкая) 
def generate_card_number(data):
    while True:
        card = ''.join([str(secrets.randbelow(10)) for _ in range(16)])
        # Проверка уникальности среди зашифрованных данных – придётся расшифровывать
        # Упрощённо: проверяем по расшифрованным значениям (для миграции)
        conflict = False
        for user in data['users'].values():
            if decrypt_data(user.get('card_number', '')) == card:
                conflict = True
                break
        if not conflict:
            return encrypt_data(card)

def generate_card_expiry():
    # Исправление: большой диапазон, криптостойкий генератор
    now = datetime.now()
    year_offset = secrets.randbelow(20)  # до 20 лет
    year = now.year + year_offset
    month = secrets.randbelow(12) + 1
    return encrypt_data(f"{month:02d}/{year % 100:02d}")

def generate_card_cvv():
    # Исправление: secrets.randbelow, 3 цифры
    cvv = f"{secrets.randbelow(1000):03d}"
    return encrypt_data(cvv)

# Исправление 5: CSRF защита 
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

def check_csrf_token():
    token = request.form.get('_csrf_token') or request.headers.get('X-CSRFToken')
    if not token or token != session.get('_csrf_token'):
        return False
    return True

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# Исправление 6: миграция с шифрованием 
def migrate_user_data(data):
    if 'groups' not in data:
        data['groups'] = {}
    for username, user_data in data['users'].items():
        if 'phone' not in user_data:
            user_data['phone'] = ''
        if 'chats' not in user_data:
            user_data['chats'] = {}
        if 'groups' not in user_data:
            user_data['groups'] = []
        if 'settings' not in user_data:
            user_data['settings'] = {'theme': 'light', 'language': 'ru'}
        if 'transfer_history' not in user_data:
            user_data['transfer_history'] = []
        # Шифруем старые данные, если они ещё не зашифрованы
        if 'card_number' not in user_data or not user_data['card_number'].startswith('gAAAAA'):
            plain_card = user_data.get('card_number', generate_card_number(data))
            if isinstance(plain_card, str) and not plain_card.startswith('gAAAAA'):
                user_data['card_number'] = encrypt_data(plain_card)
        if 'card_expiry' not in user_data or not user_data['card_expiry'].startswith('gAAAAA'):
            plain_expiry = user_data.get('card_expiry', generate_card_expiry())
            if isinstance(plain_expiry, str) and not plain_expiry.startswith('gAAAAA'):
                user_data['card_expiry'] = encrypt_data(plain_expiry)
        if 'card_cvv' not in user_data or not user_data['card_cvv'].startswith('gAAAAA'):
            plain_cvv = user_data.get('card_cvv', generate_card_cvv())
            if isinstance(plain_cvv, str) and not plain_cvv.startswith('gAAAAA'):
                user_data['card_cvv'] = encrypt_data(plain_cvv)
        if 'is_admin' not in user_data:
            user_data['is_admin'] = 0
        if 'user_id' not in user_data:
            user_data['user_id'] = generate_user_id()
        if 'last_seen' not in user_data:
            user_data['last_seen'] = time.time()
        if 'online_status' not in user_data:
            user_data['online_status'] = False
        #  Исправление 7: удаляем поддержку старых SHA256 (конвертируем при логине) 
        # В load_data мы вызовем миграцию паролей отдельно
    return data

def load_data():
    if not os.path.exists(DATA_FILE):
        admin_id = generate_user_id()
        default_admin = {
            "admin": {
                "password": bcrypt.hashpw("admin".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
                "balance": 10000.0,
                "card_number": encrypt_data("1111222233334444"),
                "phone": "",
                "is_admin": 1,
                "settings": {"theme": "light", "language": "ru"},
                "transfer_history": [],
                "chats": {},
                "groups": [],
                "user_id": admin_id,
                "card_expiry": encrypt_data("12/28"),
                "card_cvv": encrypt_data("123"),
                "last_seen": time.time(),
                "online_status": True
            }
        }
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({"users": default_admin, "groups": {}}, f, indent=4)
        return {"users": default_admin, "groups": {}}
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            data = migrate_user_data(data)
            # --- Исправление 8: конвертация старых SHA256 паролей в bcrypt ---
            for username, user_data in data['users'].items():
                pwd = user_data['password']
                if len(pwd) == 64 and all(c in '0123456789abcdef' for c in pwd):
                    # Это старый SHA256 – такого быть не должно, но на всякий случай просим сменить пароль
                    # В реальном приложении лучше отправить письмо. Здесь просто блокируем доступ.
                    user_data['password'] = 'NEED_CHANGE_LEGACY_HASH'
            save_data(data)
            return data
    except json.JSONDecodeError:
        os.remove(DATA_FILE)
        return load_data()

def save_data(data):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def update_last_seen(username):
    # Исправление: обновляем last_seen не чаще раза в минуту
    data = load_data()
    if username in data['users']:
        last = data['users'][username].get('last_seen', 0)
        if time.time() - last > 60:
            data['users'][username]['last_seen'] = time.time()
            data['users'][username]['online_status'] = True
            save_data(data)

def set_offline(username):
    data = load_data()
    if username in data['users']:
        data['users'][username]['online_status'] = False
        data['users'][username]['last_seen'] = time.time()
        save_data(data)

def add_history_entry(username, entry):
    data = load_data()
    if username in data['users']:
        data['users'][username]['transfer_history'].insert(0, entry)
        data['users'][username]['transfer_history'] = data['users'][username]['transfer_history'][:50]
        save_data(data)

def log_transaction(from_user, to_user, amount, type_desc):
    timestamp = int(time.time())
    if from_user:
        add_history_entry(from_user, {"type": type_desc, "from": from_user, "to": to_user, "amount": amount, "date": timestamp})
    if to_user:
        add_history_entry(to_user, {"type": type_desc, "from": from_user, "to": to_user, "amount": amount, "date": timestamp})

# ---------- Декораторы ----------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('Пожалуйста, войдите', 'warning')
            return redirect(url_for('login'))
        update_last_seen(session['username'])
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('Войдите', 'warning')
            return redirect(url_for('login'))
        data = load_data()
        user = data['users'].get(session['username'])
        if not user or not user.get('is_admin', 0):
            flash('Доступ запрещён', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# ---------- Контекстный процессор ----------
@app.context_processor
def inject_user():
    if 'username' in session:
        data = load_data()
        user = data['users'].get(session['username'])
        if user:
            # Для шаблонов передаём расшифрованные данные, но только там где нужно
            user_display = user.copy()
            user_display['card_number_dec'] = decrypt_data(user.get('card_number', ''))
            user_display['card_expiry_dec'] = decrypt_data(user.get('card_expiry', ''))
            user_display['card_cvv_dec'] = decrypt_data(user.get('card_cvv', ''))
            return dict(user=user_display)
    return dict(user=None)

@app.template_filter('timestamp_to_str')
def timestamp_to_str(ts):
    return datetime.fromtimestamp(ts).strftime('%H:%M %d.%m')

# ---------- Основные роуты ----------
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('profile'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember') == 'on'
        data = load_data()
        user = data['users'].get(username)
        if user:
            #  Исправление 9: регенерация сессии после входа 
            if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                # Очищаем старую сессию (фиксация)
                session.clear()
                session['username'] = username
                if remember:
                    session.permanent = True
                else:
                    session.permanent = False
                # Генерируем новый CSRF токен
                generate_csrf_token()
                update_last_seen(username)
                flash(f'Добро пожаловать, {username}!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Неверное имя или пароль', 'danger')
        else:
            flash('Неверное имя или пароль', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm_password']
        if password != confirm:
            flash('Пароли не совпадают', 'danger')
            return redirect(url_for('register'))
        if len(password) < 4:
            flash('Пароль минимум 4 символа', 'danger')
            return redirect(url_for('register'))
        data = load_data()
        if username in data['users']:
            flash('Пользователь уже существует', 'danger')
            return redirect(url_for('register'))
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        card_enc = generate_card_number(data)
        user_id = generate_user_id()
        card_expiry_enc = generate_card_expiry()
        card_cvv_enc = generate_card_cvv()
        data['users'][username] = {
            "password": hashed,
            "balance": 1000.0,
            "card_number": card_enc,
            "phone": "",
            "is_admin": 0,
            "settings": {"theme": "light", "language": "ru"},
            "transfer_history": [],
            "chats": {},
            "groups": [],
            "user_id": user_id,
            "card_expiry": card_expiry_enc,
            "card_cvv": card_cvv_enc,
            "last_seen": time.time(),
            "online_status": False
        }
        save_data(data)
        flash('Регистрация успешна! Войдите.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/profile')
@login_required
def profile():
    data = load_data()
    user = data['users'][session['username']]
    card_raw = decrypt_data(user['card_number'])
    card_display = ' '.join([card_raw[i:i+4] for i in range(0, 16, 4)]) if len(card_raw) == 16 else card_raw
    return render_template('profile.html', user=user, card_display=card_display)

@app.route('/card')
@login_required
def card_info():
    data = load_data()
    user = data['users'][session['username']]
    card_raw = decrypt_data(user['card_number'])
    card_display = ' '.join([card_raw[i:i+4] for i in range(0, 16, 4)]) if len(card_raw) == 16 else card_raw
    expiry = decrypt_data(user.get('card_expiry', ''))
    cvv = decrypt_data(user.get('card_cvv', ''))
    return render_template('card.html', user=user, card_display=card_display, expiry=expiry, cvv=cvv)

@app.route('/transfers')
@login_required
def transfers():
    data = load_data()
    balance = data['users'][session['username']]['balance']
    return render_template('transfers.html', balance=balance)

@app.route('/transfer_api', methods=['POST'])
@login_required
@rate_limit(limit_per_sec=2, key_prefix='transfer')  # Исправление 10: rate limit для переводов
def transfer_api():
    # Исправление 11: CSRF проверка для AJAX 
    csrf_token = request.headers.get('X-CSRFToken')
    if not csrf_token or csrf_token != session.get('_csrf_token'):
        return jsonify({'success': False, 'message': 'CSRF токен недействителен'}), 400
    data = request.get_json()
    to_username = data.get('to_username')
    amount = float(data.get('amount'))
    current_user = session['username']
    data_file = load_data()
    user = data_file['users'][current_user]

    if to_username == current_user:
        return jsonify({'success': False, 'message': 'Нельзя перевести самому себе'})
    if amount <= 0:
        return jsonify({'success': False, 'message': 'Сумма должна быть положительной'})
    if user['balance'] < amount:
        return jsonify({'success': False, 'message': 'Недостаточно средств'})
    if to_username not in data_file['users']:
        return jsonify({'success': False, 'message': 'Получатель не найден'})

    data_file['users'][current_user]['balance'] -= amount
    data_file['users'][to_username]['balance'] += amount
    save_data(data_file)
    log_transaction(current_user, to_username, amount, "transfer")
    return jsonify({
        'success': True,
        'message': f'Переведено {amount} ₽ пользователю {to_username}',
        'new_balance': data_file['users'][current_user]['balance']
    })

@app.route('/get_balance')
@login_required
def get_balance():
    data = load_data()
    balance = data['users'][session['username']]['balance']
    return jsonify({'balance': balance})

@app.route('/history')
@login_required
def history():
    data = load_data()
    history_list = data['users'][session['username']]['transfer_history']
    for item in history_list:
        item['date_str'] = datetime.fromtimestamp(item['date']).strftime('%Y-%m-%d %H:%M:%S')
    return render_template('history.html', history=history_list)

# ---------- Личные сообщения (чат) ----------
@app.route('/chat')
@login_required
def chat_list():
    data = load_data()
    current_user = session['username']
    dialogs = list(data['users'][current_user]['chats'].keys())
    dialog_status = {}
    for d in dialogs:
        last_seen = data['users'][d]['last_seen']
        online = data['users'][d]['online_status']
        dialog_status[d] = 'онлайн' if online else (f'был {datetime.fromtimestamp(last_seen).strftime("%H:%M %d.%m")}')
    all_users = [u for u in data['users'].keys() if u != current_user]
    return render_template('chat_list.html', dialogs=dialogs, dialog_status=dialog_status, all_users=all_users)

@app.route('/chat/<recipient>')
@login_required
def chat(recipient):
    data = load_data()
    current_user = session['username']
    if recipient not in data['users']:
        flash('Пользователь не найден', 'danger')
        return redirect(url_for('chat_list'))
    if recipient not in data['users'][current_user]['chats']:
        data['users'][current_user]['chats'][recipient] = []
        if current_user not in data['users'][recipient]['chats']:
            data['users'][recipient]['chats'][current_user] = []
        save_data(data)
    messages = data['users'][current_user]['chats'][recipient]
    messages.sort(key=lambda x: x['timestamp'])
    for msg in messages:
        if msg['from'] == recipient and not msg.get('read', False):
            msg['read'] = True
    save_data(data)
    for msg in messages:
        msg['date_str'] = datetime.fromtimestamp(msg['timestamp']).strftime('%H:%M')
    target_user = data['users'][recipient]
    target_status = 'онлайн' if target_user['online_status'] else f'был {datetime.fromtimestamp(target_user["last_seen"]).strftime("%d.%m %H:%M")}'
    return render_template('chat.html', recipient=recipient, messages=messages, target_status=target_status)

@app.route('/send_message', methods=['POST'])
@login_required
@rate_limit(limit_per_sec=3, key_prefix='msg')
def send_message():
    # CSRF проверка
    if not check_csrf_token():
        flash('Ошибка CSRF', 'danger')
        return redirect(request.referrer or url_for('chat_list'))
    recipient = request.form['recipient']
    message_text = request.form.get('message', '')
    file = request.files.get('file')
    file_url = None
    file_type = 'text'
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{uuid.uuid4().hex}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        file_url = f'/uploads/{filename}'
        if file.content_type.startswith('image/'):
            file_type = 'image'
        elif file.content_type.startswith('audio/'):
            file_type = 'audio'
        else:
            file_type = 'file'
    if not message_text and not file_url:
        flash('Нет сообщения', 'danger')
        return redirect(url_for('chat', recipient=recipient))
    data = load_data()
    current_user = session['username']
    msg = {
        'id': int(time.time()*1000),
        'from': current_user,
        'to': recipient,
        'text': message_text,
        'timestamp': time.time(),
        'type': file_type,
        'file': file_url,
        'delivered': False,
        'read': False
    }
    if recipient not in data['users'][current_user]['chats']:
        data['users'][current_user]['chats'][recipient] = []
    data['users'][current_user]['chats'][recipient].append(msg)
    if current_user not in data['users'][recipient]['chats']:
        data['users'][recipient]['chats'][current_user] = []
    data['users'][recipient]['chats'][current_user].append(msg)
    save_data(data)
    return redirect(url_for('chat', recipient=recipient))

@app.route('/mark_delivered', methods=['POST'])
@login_required
def mark_delivered():
    data = load_data()
    current_user = session['username']
    sender = request.json.get('sender')
    if sender and sender in data['users'][current_user]['chats']:
        for msg in data['users'][current_user]['chats'][sender]:
            if msg['to'] == current_user and msg['from'] == sender and not msg.get('delivered', False):
                msg['delivered'] = True
        save_data(data)
    return jsonify({'status': 'ok'})

@app.route('/get_updates/<recipient>')
@login_required
def get_updates(recipient):
    data = load_data()
    current_user = session['username']
    last_id = int(request.args.get('last_id', 0))
    timeout = 30
    start = time.time()
    while time.time() - start < timeout:
        data = load_data()
        if recipient in data['users'][current_user]['chats']:
            messages = data['users'][current_user]['chats'][recipient]
            new_msgs = [m for m in messages if m['id'] > last_id and m['from'] == recipient]
            if new_msgs:
                for m in new_msgs:
                    m['date_str'] = datetime.fromtimestamp(m['timestamp']).strftime('%H:%M')
                return jsonify({'messages': new_msgs})
        time.sleep(1)
    return jsonify({'messages': []})

@app.route('/search_user_autocomplete')
@login_required
@rate_limit(limit_per_sec=5, key_prefix='search')
def search_user_autocomplete():
    q = request.args.get('q', '').lower()
    if len(q) < 1:
        return jsonify([])
    data = load_data()
    current_user = session['username']
    results = [{'username': u} for u in data['users'] if u != current_user and u.lower().startswith(q)]
    return jsonify(results[:5])

# Исправление 12: контроль доступа к файлам 
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    if 'username' not in session:
        return "Unauthorized", 401
    current_user = session['username']
    data = load_data()
    # Проверяем, участвует ли текущий пользователь в диалоге, где был отправлен этот файл
    allowed = False
    # Ищем в личных сообщениях
    for user, chats in data['users'].items():
        if user == current_user:
            for recipient, messages in chats.get('chats', {}).items():
                for msg in messages:
                    if msg.get('file') and msg['file'].endswith(filename):
                        allowed = True
                        break
                if allowed:
                    break
        if allowed:
            break
    # Если не нашли, ищем в группах
    if not allowed:
        for gid, group in data.get('groups', {}).items():
            if current_user in group.get('members', []):
                for msg in group.get('messages', []):
                    if msg.get('file') and msg['file'].endswith(filename):
                        allowed = True
                        break
            if allowed:
                break
    if not allowed:
        return "Forbidden", 403
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ---------- Групповые чаты ----------
@app.route('/groups')
@login_required
def list_groups():
    data = load_data()
    current_user = session['username']
    my_groups = [gid for gid, grp in data['groups'].items() if current_user in grp.get('members', [])]
    groups_info = {gid: data['groups'][gid] for gid in my_groups if gid in data['groups']}
    return render_template('groups.html', groups=groups_info)

@app.route('/create_group', methods=['POST'])
@login_required
def create_group():
    if not check_csrf_token():
        flash('CSRF ошибка', 'danger')
        return redirect(url_for('list_groups'))
    name = request.form['name']
    data = load_data()
    current_user = session['username']
    group_id = str(uuid.uuid4())
    data['groups'][group_id] = {
        'name': name,
        'members': [current_user],
        'messages': [],
        'created_by': current_user,
        'created_at': time.time()
    }
    data['users'][current_user]['groups'].append(group_id)
    save_data(data)
    flash('Группа создана!', 'success')
    return redirect(url_for('group_chat', group_id=group_id))

@app.route('/add_to_group', methods=['POST'])
@login_required
def add_to_group():
    if not check_csrf_token():
        flash('CSRF ошибка', 'danger')
        return redirect(url_for('list_groups'))
    group_id = request.form['group_id']
    username = request.form['username']
    data = load_data()
    current_user = session['username']
    group = data['groups'].get(group_id)
    if not group or current_user not in group['members']:
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('list_groups'))
    if username not in data['users']:
        flash('Пользователь не найден', 'danger')
    elif username in group['members']:
        flash('Уже в группе', 'warning')
    else:
        group['members'].append(username)
        data['users'][username]['groups'].append(group_id)
        save_data(data)
        flash(f'{username} добавлен в группу', 'success')
    return redirect(url_for('group_chat', group_id=group_id))

@app.route('/group/<group_id>')
@login_required
def group_chat(group_id):
    data = load_data()
    current_user = session['username']
    group = data['groups'].get(group_id)
    if not group or current_user not in group['members']:
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('list_groups'))
    return render_template('group_chat.html', group=group, group_id=group_id)

@app.route('/send_group_message', methods=['POST'])
@login_required
@rate_limit(limit_per_sec=3, key_prefix='group_msg')
def send_group_message():
    if not check_csrf_token():
        flash('CSRF ошибка', 'danger')
        return redirect(request.referrer or url_for('list_groups'))
    group_id = request.form['group_id']
    message_text = request.form.get('message', '')
    file = request.files.get('file')
    file_url = None
    file_type = 'text'
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{uuid.uuid4().hex}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        file_url = f'/uploads/{filename}'
        if file.content_type.startswith('image/'):
            file_type = 'image'
        elif file.content_type.startswith('audio/'):
            file_type = 'audio'
        else:
            file_type = 'file'
    if not message_text and not file_url:
        flash('Нет сообщения', 'danger')
        return redirect(url_for('group_chat', group_id=group_id))
    data = load_data()
    current_user = session['username']
    group = data['groups'].get(group_id)
    if not group or current_user not in group['members']:
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('list_groups'))
    msg = {
        'id': int(time.time()*1000),
        'from': current_user,
        'text': message_text,
        'timestamp': time.time(),
        'type': file_type,
        'file': file_url
    }
    group['messages'].append(msg)
    save_data(data)
    return redirect(url_for('group_chat', group_id=group_id))

# Админка 
@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_panel():
    data = load_data()
    if request.method == 'POST':
        if not check_csrf_token():
            flash('CSRF ошибка', 'danger')
            return redirect(url_for('admin_panel'))
        action = request.form.get('action')
        target_user = request.form.get('target_user')
        if action == 'change_balance':
            amount = float(request.form['amount'])
            if target_user in data['users']:
                data['users'][target_user]['balance'] += amount
                save_data(data)
                log_transaction('admin', target_user, amount, "admin_change")
                flash(f'Баланс {target_user} изменён на {amount}', 'success')
            else:
                flash('Пользователь не найден', 'danger')
        elif action == 'make_admin':
            if target_user in data['users']:
                data['users'][target_user]['is_admin'] = 1
                save_data(data)
                flash(f'{target_user} теперь админ', 'success')
            else:
                flash('Не найден', 'danger')
        elif action == 'remove_admin':
            if target_user in data['users']:
                data['users'][target_user]['is_admin'] = 0
                save_data(data)
                flash(f'{target_user} больше не админ', 'success')
            else:
                flash('Не найден', 'danger')
        return redirect(url_for('admin_panel'))
    #  Исправление 13: маскируем номера карт 
    for user in data['users'].values():
        card_raw = decrypt_data(user.get('card_number', ''))
        if len(card_raw) >= 4:
            user['card_masked'] = '**** **** **** ' + card_raw[-4:]
        else:
            user['card_masked'] = '****'
    return render_template('admin.html', users=data['users'])

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    data = load_data()
    user = data['users'][session['username']]
    if request.method == 'POST':
        if not check_csrf_token():
            flash('CSRF ошибка', 'danger')
            return redirect(url_for('settings'))
        if 'old_password' in request.form:
            old = request.form['old_password']
            new = request.form['new_password']
            confirm = request.form['confirm_password']
            if not bcrypt.checkpw(old.encode('utf-8'), user['password'].encode('utf-8')):
                flash('Старый пароль неверен', 'danger')
            elif new != confirm:
                flash('Пароли не совпадают', 'danger')
            elif len(new) < 4:
                flash('Пароль минимум 4 символа', 'danger')
            else:
                new_hashed = bcrypt.hashpw(new.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                user['password'] = new_hashed
                save_data(data)
                flash('Пароль изменён', 'success')
        if 'theme' in request.form:
            # Экранирование будет в шаблоне
            user['settings']['theme'] = request.form['theme']
            save_data(data)
            flash('Тема обновлена', 'success')
        if 'language' in request.form:
            user['settings']['language'] = request.form['language']
            save_data(data)
            flash('Язык обновлён', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html', user=user)

@app.route('/logout')
def logout():
    if 'username' in session:
        set_offline(session['username'])
    #  Исправление 14: полная очистка сессии на сервере 
    session.clear()
    flash('Вы вышли', 'info')
    return redirect(url_for('login'))

# Исправление 15: отключаем debug по умолчанию 
if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, port=5000)
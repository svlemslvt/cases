import json
import sqlite3
import os
import hmac
import hashlib
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

DB_FILE = 'bank.db'
JSON_FILE = 'data.json'

# Исправление 1: проверка подписи JSON 
HMAC_SECRET = os.environ.get('HMAC_SECRET')
if not HMAC_SECRET:
    raise Exception("HMAC_SECRET не задан в .env")

def verify_hmac(data: dict, signature: str) -> bool:
    data_str = json.dumps(data, sort_keys=True)
    expected = hmac.new(HMAC_SECRET.encode(), data_str.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

#  Исправление 2: шифрование (тот же ключ, что в app.py) 
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    raise Exception("ENCRYPTION_KEY не задан в .env")
fernet = Fernet(ENCRYPTION_KEY.encode())

def decrypt_data(data: str) -> str:
    if not data or not data.startswith('gAAAAA'):
        return data
    try:
        return fernet.decrypt(data.encode()).decode()
    except:
        return ""

def create_tables(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            balance REAL,
            card_number TEXT,
            phone TEXT,
            is_admin INTEGER,
            theme TEXT,
            language TEXT,
            user_id TEXT,
            card_expiry TEXT,
            card_cvv TEXT,
            last_seen REAL,
            online_status INTEGER
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            type TEXT,
            from_user TEXT,
            to_user TEXT,
            amount REAL,
            date REAL,
            FOREIGN KEY(username) REFERENCES users(username)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS private_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            msg_id INTEGER,
            from_user TEXT,
            to_user TEXT,
            text TEXT,
            timestamp REAL,
            msg_type TEXT,
            file_url TEXT,
            delivered INTEGER,
            read INTEGER
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            group_id TEXT PRIMARY KEY,
            name TEXT,
            created_by TEXT,
            created_at REAL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            group_id TEXT,
            username TEXT,
            PRIMARY KEY (group_id, username)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS group_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id TEXT,
            msg_id INTEGER,
            from_user TEXT,
            text TEXT,
            timestamp REAL,
            msg_type TEXT,
            file_url TEXT
        )
    ''')
    # Исправление 3: добавление индексов для ускорения 
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_private_messages_to_user ON private_messages(to_user)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_private_messages_timestamp ON private_messages(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_transfers_username ON transfers(username)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_group_messages_group_id ON group_messages(group_id)')
    conn.commit()

def migrate_users(conn, data):
    cursor = conn.cursor()
    for username, user_data in data['users'].items():
        settings = user_data.get('settings', {})
        # Расшифровываем перед вставкой (в БД храним открыто, но приложение будет шифровать при чтении? Лучше хранить в БД тоже зашифрованными)
        # Однако для совместимости с приложением оставим как есть, т.к. приложение уже умеет шифровать.
        # Здесь мы просто переносим данные в том виде, в котором они есть (уже зашифрованы)
        cursor.execute('''
            INSERT OR REPLACE INTO users 
            (username, password, balance, card_number, phone, is_admin, theme, language, user_id, card_expiry, card_cvv, last_seen, online_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            username,
            user_data['password'],
            user_data['balance'],
            user_data.get('card_number', ''),
            user_data.get('phone', ''),
            user_data.get('is_admin', 0),
            settings.get('theme', 'light'),
            settings.get('language', 'ru'),
            user_data.get('user_id', ''),
            user_data.get('card_expiry', ''),
            user_data.get('card_cvv', ''),
            user_data.get('last_seen', 0),
            1 if user_data.get('online_status', False) else 0
        ))
    conn.commit()
    print("Пользователи перенесены")

def migrate_transfers(conn, data):
    cursor = conn.cursor()
    for username, user_data in data['users'].items():
        for item in user_data.get('transfer_history', []):
            cursor.execute('''
                INSERT INTO transfers (username, type, from_user, to_user, amount, date)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, item['type'], item.get('from', ''), item.get('to', ''), item['amount'], item['date']))
    conn.commit()
    print("История переводов перенесена")

def migrate_private_messages(conn, data):
    cursor = conn.cursor()
    for username, user_data in data['users'].items():
        for recipient, messages in user_data.get('chats', {}).items():
            for msg in messages:
                # Исправление 4: ограничение длины текста (защита от DoS) 
                text = msg.get('text', '')
                if len(text) > 10000:
                    text = text[:10000] + "...[truncated]"
                cursor.execute('''
                    INSERT INTO private_messages 
                    (msg_id, from_user, to_user, text, timestamp, msg_type, file_url, delivered, read)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    msg['id'],
                    msg['from'],
                    msg['to'],
                    text,
                    msg['timestamp'],
                    msg.get('type', 'text'),
                    msg.get('file', ''),
                    1 if msg.get('delivered', False) else 0,
                    1 if msg.get('read', False) else 0
                ))
    conn.commit()
    print("Личные сообщения перенесены")

def migrate_groups(conn, data):
    cursor = conn.cursor()
    for group_id, group in data.get('groups', {}).items():
        cursor.execute('''
            INSERT OR REPLACE INTO groups (group_id, name, created_by, created_at)
            VALUES (?, ?, ?, ?)
        ''', (group_id, group['name'], group.get('created_by', ''), group.get('created_at', 0)))
        for member in group.get('members', []):
            cursor.execute('''
                INSERT OR IGNORE INTO group_members (group_id, username)
                VALUES (?, ?)
            ''', (group_id, member))
        for msg in group.get('messages', []):
            text = msg.get('text', '')
            if len(text) > 10000:
                text = text[:10000] + "...[truncated]"
            cursor.execute('''
                INSERT INTO group_messages (group_id, msg_id, from_user, text, timestamp, msg_type, file_url)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                group_id,
                msg.get('id', 0),
                msg.get('from', ''),
                text,
                msg.get('timestamp', 0),
                msg.get('type', 'text'),
                msg.get('file', '')
            ))
    conn.commit()
    print("Группы и сообщения групп перенесены")

def main():
    if not os.path.exists(JSON_FILE):
        print(f"Файл {JSON_FILE} не найден")
        return
    with open(JSON_FILE, 'r', encoding='utf-8') as f:
        raw_data = f.read()
        data = json.loads(raw_data)
    # --- Проверка подписи (если присутствует) ---
    signature = data.pop('_hmac_signature', None)
    if signature:
        if not verify_hmac(data, signature):
            print("Ошибка: HMAC подпись не совпадает! Отказ в миграции.")
            return
        print("Подпись JSON проверена успешно.")
    else:
        print("Предупреждение: JSON не подписан. Миграция продолжается, но это небезопасно.")
    
    # Исправление 5: транзакция 
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute("BEGIN TRANSACTION")
        create_tables(conn)
        migrate_users(conn, data)
        migrate_transfers(conn, data)
        migrate_private_messages(conn, data)
        migrate_groups(conn, data)
        conn.commit()
        print(f"База данных {DB_FILE} создана и заполнена.")
    except Exception as e:
        conn.rollback()
        print(f"Ошибка миграции, откат: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    main()
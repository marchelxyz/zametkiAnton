import os
import json
import hashlib
import hmac
import uuid
import base64
import requests
import atexit
from urllib.parse import unquote, parse_qs
from flask import Flask, request, jsonify, render_template, send_from_directory
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from nacl.signing import SigningKey
from nacl.exceptions import BadSignature
from database import (
    init_db, create_note, get_notes_by_user, get_note_by_id, update_note, delete_note,
    create_task, get_tasks_by_user, get_task_by_id, update_task, delete_task,
    get_tasks_due_for_notification, update_task_next_notification,
    create_attachment, get_attachments_by_note, get_attachment_by_id, delete_attachment,
    get_note_with_attachments
)
from storage import (
    is_gcs_available, generate_gcs_path, upload_to_gcs, download_from_gcs, delete_from_gcs
)

# Загружаем переменные окружения
load_dotenv()

app = Flask(__name__)

# Получаем токен бота из переменных окружения
BOT_TOKEN = os.getenv("BOT_TOKEN", "")

# Конфигурация загрузки файлов
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB максимум
ALLOWED_EXTENSIONS = {
    'image': {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'},
    'document': {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'zip', 'rar'}
}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Создаём папку для загрузок если её нет
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Планировщик для периодических задач
scheduler = BackgroundScheduler()


def get_file_type(filename: str) -> str:
    """Определить тип файла по расширению"""
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    if ext in ALLOWED_EXTENSIONS['image']:
        return 'image'
    elif ext in ALLOWED_EXTENSIONS['document']:
        return 'document'
    return None


def allowed_file(filename: str) -> bool:
    """Проверить допустимость файла"""
    return get_file_type(filename) is not None


def generate_stored_filename(original_filename: str) -> str:
    """Сгенерировать уникальное имя файла для хранения"""
    ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
    unique_name = f"{uuid.uuid4().hex}"
    if ext:
        unique_name = f"{unique_name}.{ext}"
    return unique_name


def send_telegram_message(chat_id: int, text: str) -> bool:
    """Отправить сообщение через Telegram Bot API"""
    if not BOT_TOKEN:
        print(f"[DEBUG] BOT_TOKEN не задан. Сообщение для {chat_id}: {text}")
        return False
    
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML"
        }
        response = requests.post(url, json=payload, timeout=10)
        result = response.json()
        
        if result.get("ok"):
            print(f"[OK] Сообщение отправлено пользователю {chat_id}")
            return True
        else:
            print(f"[ERROR] Ошибка отправки: {result}")
            return False
    except Exception as e:
        print(f"[ERROR] Исключение при отправке сообщения: {e}")
        return False


def check_and_send_notifications():
    """Проверка и отправка уведомлений по расписанию"""
    with app.app_context():
        try:
            tasks = get_tasks_due_for_notification()
            for task in tasks:
                message = f"🔔 <b>Напоминание!</b>\n\n" \
                          f"📌 <b>{task.title}</b>\n"
                if task.description:
                    message += f"📝 {task.description}\n"
                message += f"\n⏰ Следующее напоминание через {task.interval_minutes} мин."
                
                # Отправляем уведомление
                send_telegram_message(task.user_id, message)
                
                # Обновляем время следующего уведомления
                update_task_next_notification(task.id)
                
        except Exception as e:
            print(f"[ERROR] Ошибка при проверке уведомлений: {e}")


def verify_telegram_signature(bot_token: str, data_check_string: str, signature_b64: str) -> bool:
    """
    Проверка Ed25519 подписи (новый формат Telegram Mini Apps с Bot API 6.7+).
    
    Алгоритм:
    1. Создаём seed = SHA256(bot_token)
    2. Из seed создаём Ed25519 keypair
    3. Проверяем подпись signature над data_check_string
    """
    try:
        # Создаём seed из SHA256(bot_token)
        seed = hashlib.sha256(bot_token.encode()).digest()
        
        # Создаём SigningKey (приватный ключ) из seed
        signing_key = SigningKey(seed)
        
        # Получаем VerifyKey (публичный ключ)
        verify_key = signing_key.verify_key
        
        # Декодируем signature из base64
        signature = base64.b64decode(signature_b64)
        
        # Проверяем подпись
        verify_key.verify(data_check_string.encode(), signature)
        return True
        
    except BadSignature:
        return False
    except Exception as e:
        print(f"[AUTH] Ошибка проверки Ed25519 подписи: {e}")
        return False


def verify_telegram_hash(bot_token: str, data_check_string: str, received_hash: str) -> bool:
    """
    Проверка HMAC-SHA256 хэша (старый формат Telegram Mini Apps).
    
    Алгоритм:
    1. secret_key = HMAC_SHA256("WebAppData", bot_token)
    2. calculated_hash = HMAC_SHA256(secret_key, data_check_string)
    3. Сравниваем calculated_hash с received_hash
    """
    # Создаём секретный ключ согласно документации Telegram
    secret_key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    
    # Вычисляем hash для проверки
    calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    
    return hmac.compare_digest(calculated_hash, received_hash)


def verify_telegram_data(init_data: str) -> dict:
    """
    Проверка данных от Telegram Mini App.
    Возвращает данные пользователя если валидация успешна.
    
    Поддерживает два формата:
    1. Новый формат (Bot API 6.7+) с signature (Ed25519)
    2. Старый формат с hash (HMAC-SHA256)
    
    ВАЖНО: init_data от Telegram приходит в URL-encoded формате,
    поэтому значения нужно декодировать перед проверкой подписи.
    """
    # Режим отладки для тестирования вне Telegram
    debug_mode = os.getenv("DEBUG", "false").lower() == "true"
    
    # В режиме отладки или без BOT_TOKEN - работаем с тестовыми данными
    if not BOT_TOKEN or debug_mode:
        if not BOT_TOKEN:
            print("[DEBUG] BOT_TOKEN не задан, используем тестовые данные")
        else:
            print("[DEBUG] DEBUG режим включен, используем тестовые данные")
        return {"id": 123456789, "first_name": "Test", "username": "testuser"}
    
    # Проверяем, что init_data не пустая и содержит корректный формат
    if not init_data or '=' not in init_data:
        # Более информативное логирование
        init_data_preview = init_data[:50] if init_data else "(пустая)"
        print(f"[AUTH] Ошибка верификации: init_data пустая или некорректная")
        print(f"[AUTH]   - init_data длина: {len(init_data) if init_data else 0}")
        print(f"[AUTH]   - init_data превью: {init_data_preview}")
        print(f"[AUTH]   - Убедитесь, что приложение открыто через Telegram Mini App")
        print(f"[AUTH]   - Или включите DEBUG=true для работы без Telegram")
        return None
    
    try:
        # Парсим init_data с URL-декодированием значений
        # КРИТИЧНО: Telegram отправляет данные в URL-encoded формате
        parsed_data = {}
        for pair in init_data.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                # URL-декодируем значение
                parsed_data[key] = unquote(value)
        
        # Определяем формат верификации: signature (новый) или hash (старый)
        received_signature = parsed_data.pop('signature', '')
        received_hash = parsed_data.pop('hash', '')
        
        if not received_signature and not received_hash:
            print("[AUTH] Ошибка верификации: ни signature, ни hash не найдены в init_data")
            print(f"[AUTH]   - Доступные ключи: {list(parsed_data.keys())}")
            return None
        
        # Проверяем auth_date (данные не должны быть старше 24 часов)
        auth_date_str = parsed_data.get('auth_date', '')
        if auth_date_str:
            try:
                from datetime import datetime, timezone
                auth_date = int(auth_date_str)
                now = int(datetime.now(timezone.utc).timestamp())
                age_seconds = now - auth_date
                age_hours = age_seconds / 3600
                
                # Предупреждение если данные старые (но не блокируем - иногда часы сервера расходятся)
                if age_seconds > 86400:  # 24 часа
                    print(f"[AUTH] Предупреждение: auth_date очень старый ({age_hours:.1f} часов)")
                elif age_seconds > 3600:  # 1 час
                    print(f"[AUTH] Инфо: auth_date имеет возраст {age_hours:.1f} часов")
                    
            except (ValueError, TypeError) as e:
                print(f"[AUTH] Не удалось проверить auth_date: {e}")
        
        # Сортируем по ключу и создаём строку для проверки подписи
        # Формат: key=value\nkey=value\n...
        data_check_string = '\n'.join(f"{k}={v}" for k, v in sorted(parsed_data.items()))
        
        # Проверяем подпись в зависимости от формата
        verification_success = False
        verification_method = ""
        
        if received_signature:
            # Новый формат с Ed25519 signature (Bot API 6.7+)
            verification_method = "signature (Ed25519)"
            verification_success = verify_telegram_signature(BOT_TOKEN, data_check_string, received_signature)
            
            if not verification_success:
                print(f"[AUTH] ✗ Ошибка верификации: signature не прошла проверку Ed25519")
                print(f"[AUTH]   - signature (первые 20 символов): {received_signature[:20]}...")
                print(f"[AUTH]   - BOT_TOKEN длина: {len(BOT_TOKEN)}, начинается с: {BOT_TOKEN[:10]}...")
                print(f"[AUTH]   - Проверьте, что BOT_TOKEN совпадает с токеном бота в BotFather")
                print(f"[AUTH]   - Ключи в данных: {list(parsed_data.keys())}")
        
        elif received_hash:
            # Старый формат с HMAC-SHA256 hash
            verification_method = "hash (HMAC-SHA256)"
            verification_success = verify_telegram_hash(BOT_TOKEN, data_check_string, received_hash)
            
            if not verification_success:
                # Вычисляем hash для отладки
                secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
                calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
                
                print(f"[AUTH] ✗ Ошибка верификации: hash не совпадает")
                print(f"[AUTH]   - Получен: {received_hash[:20]}...")
                print(f"[AUTH]   - Вычислен: {calculated_hash[:20]}...")
                print(f"[AUTH]   - BOT_TOKEN длина: {len(BOT_TOKEN)}, начинается с: {BOT_TOKEN[:10]}...")
                print(f"[AUTH]   - Проверьте, что BOT_TOKEN совпадает с токеном бота в BotFather")
                print(f"[AUTH]   - Ключи в данных: {list(parsed_data.keys())}")
        
        if verification_success:
            # Подпись верна, извлекаем данные пользователя
            user_json = parsed_data.get('user', '{}')
            user_data = json.loads(user_json)
            print(f"[AUTH] ✓ Верификация успешна ({verification_method}) для пользователя: {user_data.get('id')} ({user_data.get('username', 'no username')})")
            return user_data
        
        return None
            
    except json.JSONDecodeError as e:
        print(f"[AUTH] Ошибка верификации: некорректный JSON в user data: {e}")
        return None
    except Exception as e:
        print(f"[AUTH] Ошибка верификации: {e}")
        import traceback
        traceback.print_exc()
        return None


@app.route('/')
def index():
    """Главная страница Mini App"""
    return render_template('index.html')


@app.route('/api/notes', methods=['GET'])
def api_get_notes():
    """Получить все заметки пользователя"""
    init_data = request.headers.get('X-Telegram-Init-Data', '')
    user = verify_telegram_data(init_data)
    
    if not user:
        # Возвращаем более детальную информацию об ошибке
        error_details = {
            "error": "Unauthorized",
            "message": "Ошибка авторизации. Пожалуйста, перезапустите приложение через Telegram.",
            "init_data_received": bool(init_data),
            "init_data_length": len(init_data) if init_data else 0
        }
        print(f"[API] /api/notes GET - Ошибка авторизации, init_data длина: {len(init_data) if init_data else 0}")
        return jsonify(error_details), 401
    
    user_id = user.get('id')
    notes = get_notes_by_user(user_id)
    
    result = []
    for note in notes:
        attachments = get_attachments_by_note(note.id)
        result.append({
            "id": note.id,
            "title": note.title,
            "content": note.content,
            "created_at": note.created_at.isoformat() if note.created_at else None,
            "updated_at": note.updated_at.isoformat() if note.updated_at else None,
            "attachments": [
                {
                    "id": att.id,
                    "filename": att.filename,
                    "file_type": att.file_type,
                    "file_size": att.file_size
                }
                for att in attachments
            ]
        })
    
    return jsonify({"notes": result})


@app.route('/api/notes', methods=['POST'])
def api_create_note():
    """Создать новую заметку"""
    init_data = request.headers.get('X-Telegram-Init-Data', '')
    user = verify_telegram_data(init_data)
    
    if not user:
        print("[API] /api/notes POST - Ошибка авторизации")
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    if not data:
        print("[API] /api/notes POST - Нет данных в запросе")
        return jsonify({"error": "No data provided"}), 400
    
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()
    
    if not title:
        print("[API] /api/notes POST - Пустой заголовок")
        return jsonify({"error": "Title is required"}), 400
    
    user_id = user.get('id')
    print(f"[API] /api/notes POST - Создание заметки для user_id={user_id}, title='{title[:30]}...'")
    
    try:
        note = create_note(user_id, title, content)
        print(f"[API] /api/notes POST - Заметка создана, id={note.id}")
        
        return jsonify({
            "id": note.id,
            "title": note.title,
            "content": note.content,
            "created_at": note.created_at.isoformat() if note.created_at else None
        }), 201
    except Exception as e:
        print(f"[API] /api/notes POST - Ошибка создания: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Failed to create note"}), 500


@app.route('/api/notes/<int:note_id>', methods=['GET'])
def api_get_note(note_id):
    """Получить заметку по ID"""
    init_data = request.headers.get('X-Telegram-Init-Data', '')
    user = verify_telegram_data(init_data)
    
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = user.get('id')
    note, attachments = get_note_with_attachments(note_id, user_id)
    
    if not note:
        return jsonify({"error": "Note not found"}), 404
    
    return jsonify({
        "id": note.id,
        "title": note.title,
        "content": note.content,
        "created_at": note.created_at.isoformat() if note.created_at else None,
        "updated_at": note.updated_at.isoformat() if note.updated_at else None,
        "attachments": [
            {
                "id": att.id,
                "filename": att.filename,
                "file_type": att.file_type,
                "file_size": att.file_size
            }
            for att in attachments
        ]
    })


@app.route('/api/notes/<int:note_id>', methods=['PUT'])
def api_update_note(note_id):
    """Обновить заметку"""
    init_data = request.headers.get('X-Telegram-Init-Data', '')
    user = verify_telegram_data(init_data)
    
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    
    user_id = user.get('id')
    note = update_note(note_id, user_id, title, content)
    
    if not note:
        return jsonify({"error": "Note not found"}), 404
    
    return jsonify({
        "id": note.id,
        "title": note.title,
        "content": note.content,
        "updated_at": note.updated_at.isoformat() if note.updated_at else None
    })


@app.route('/api/notes/<int:note_id>', methods=['DELETE'])
def api_delete_note(note_id):
    """Удалить заметку"""
    init_data = request.headers.get('X-Telegram-Init-Data', '')
    user = verify_telegram_data(init_data)
    
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = user.get('id')
    
    # Удаляем заметку (вложения удалятся каскадно благодаря CASCADE в БД)
    success = delete_note(note_id, user_id)
    
    if not success:
        return jsonify({"error": "Note not found"}), 404
    
    return jsonify({"success": True})


# ==================== API для вложений ====================

@app.route('/api/notes/<int:note_id>/attachments', methods=['POST'])
def api_upload_attachment(note_id):
    """Загрузить вложение к заметке (в Google Cloud Storage или БД как fallback)"""
    init_data = request.headers.get('X-Telegram-Init-Data', '')
    user = verify_telegram_data(init_data)
    
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = user.get('id')
    
    # Проверяем, что заметка существует и принадлежит пользователю
    note = get_note_by_id(note_id, user_id)
    if not note:
        return jsonify({"error": "Note not found"}), 404
    
    # Проверяем наличие файла
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400
    
    # Генерируем безопасное имя файла
    original_filename = secure_filename(file.filename)
    file_type = get_file_type(original_filename)
    
    # Читаем данные файла в память
    file_data = file.read()
    file_size = len(file_data)
    
    # Проверяем размер (16 МБ максимум)
    if file_size > MAX_CONTENT_LENGTH:
        return jsonify({"error": "File too large (max 16 MB)"}), 400
    
    # Определяем MIME тип
    mime_type = file.content_type
    
    # Пробуем загрузить в Google Cloud Storage
    gcs_path = None
    file_data_for_db = None
    
    if is_gcs_available():
        # Генерируем путь в GCS
        gcs_path = generate_gcs_path(user_id, note_id, original_filename)
        
        # Загружаем в GCS
        success, result = upload_to_gcs(file_data, gcs_path, mime_type or 'application/octet-stream')
        
        if success:
            print(f"[UPLOAD] Файл загружен в GCS: {gcs_path}")
        else:
            # Если GCS не сработал, сохраняем в БД
            print(f"[UPLOAD] Ошибка GCS, сохраняем в БД: {result}")
            gcs_path = None
            file_data_for_db = file_data
    else:
        # GCS недоступен, сохраняем в БД
        print("[UPLOAD] GCS недоступен, сохраняем в БД")
        file_data_for_db = file_data
    
    # Создаём запись в БД
    attachment = create_attachment(
        note_id=note_id,
        filename=original_filename,
        file_type=file_type,
        file_data=file_data_for_db,
        mime_type=mime_type,
        file_size=file_size,
        gcs_path=gcs_path
    )
    
    return jsonify({
        "id": attachment.id,
        "filename": attachment.filename,
        "file_type": attachment.file_type,
        "file_size": attachment.file_size,
        "created_at": attachment.created_at.isoformat() if attachment.created_at else None
    }), 201


@app.route('/api/attachments/<int:attachment_id>', methods=['GET'])
def api_get_attachment(attachment_id):
    """Скачать вложение (из Google Cloud Storage или БД)"""
    init_data = request.headers.get('X-Telegram-Init-Data', '')
    user = verify_telegram_data(init_data)
    
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = user.get('id')
    
    # Получаем вложение с данными
    attachment = get_attachment_by_id(attachment_id)
    if not attachment:
        return jsonify({"error": "Attachment not found"}), 404
    
    # Проверяем, что заметка принадлежит пользователю
    note = get_note_by_id(attachment.note_id, user_id)
    if not note:
        return jsonify({"error": "Attachment not found"}), 404
    
    # Пробуем получить файл из GCS (приоритетно)
    file_data = None
    content_type = attachment.mime_type or 'application/octet-stream'
    
    if attachment.gcs_path:
        # Файл хранится в Google Cloud Storage
        success, data, result_type = download_from_gcs(attachment.gcs_path)
        if success:
            file_data = data
            content_type = result_type
        else:
            print(f"[DOWNLOAD] Ошибка GCS: {result_type}, пробуем БД")
    
    # Fallback: файл в БД
    if file_data is None and attachment.file_data:
        file_data = attachment.file_data
    
    # Проверяем наличие данных файла
    if file_data is None:
        return jsonify({"error": "File data not found"}), 404
    
    # Возвращаем файл
    from flask import Response
    response = Response(
        file_data,
        mimetype=content_type
    )
    response.headers['Content-Disposition'] = f'inline; filename="{attachment.filename}"'
    response.headers['Content-Length'] = len(file_data)
    return response


@app.route('/api/attachments/<int:attachment_id>', methods=['DELETE'])
def api_delete_attachment(attachment_id):
    """Удалить вложение (из Google Cloud Storage и БД)"""
    init_data = request.headers.get('X-Telegram-Init-Data', '')
    user = verify_telegram_data(init_data)
    
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = user.get('id')
    
    # Получаем вложение
    attachment = get_attachment_by_id(attachment_id)
    if not attachment:
        return jsonify({"error": "Attachment not found"}), 404
    
    # Проверяем, что заметка принадлежит пользователю
    note = get_note_by_id(attachment.note_id, user_id)
    if not note:
        return jsonify({"error": "Attachment not found"}), 404
    
    # Удаляем файл из GCS если он там хранится
    if attachment.gcs_path:
        delete_from_gcs(attachment.gcs_path)
    
    # Удаляем запись из БД
    delete_attachment(attachment_id)
    
    return jsonify({"success": True})


@app.route('/health')
def health():
    """Health check для Railway"""
    return jsonify({"status": "ok"})


@app.route('/api/debug/auth', methods=['GET'])
def debug_auth():
    """Диагностика авторизации (только для отладки)"""
    init_data = request.headers.get('X-Telegram-Init-Data', '')
    
    debug_info = {
        "init_data_present": bool(init_data),
        "init_data_length": len(init_data) if init_data else 0,
        "init_data_has_equals": '=' in init_data if init_data else False,
        "init_data_has_hash": 'hash=' in init_data if init_data else False,
        "init_data_has_user": 'user=' in init_data if init_data else False,
        "bot_token_configured": bool(BOT_TOKEN),
        "bot_token_length": len(BOT_TOKEN) if BOT_TOKEN else 0,
        "debug_mode": os.getenv("DEBUG", "false").lower() == "true"
    }
    
    # Парсим init_data для анализа
    if init_data and '=' in init_data:
        try:
            parsed = {}
            for pair in init_data.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    parsed[key] = unquote(value)
            
            debug_info["parsed_keys"] = list(parsed.keys())
            
            # Проверяем auth_date
            if 'auth_date' in parsed:
                try:
                    from datetime import datetime, timezone
                    auth_ts = int(parsed['auth_date'])
                    auth_date = datetime.fromtimestamp(auth_ts, timezone.utc)
                    now = datetime.now(timezone.utc)
                    age = now - auth_date
                    debug_info["auth_date"] = auth_date.isoformat()
                    debug_info["auth_age_seconds"] = int(age.total_seconds())
                    debug_info["auth_age_hours"] = round(age.total_seconds() / 3600, 2)
                except:
                    pass
            
            # Проверяем user данные
            if 'user' in parsed:
                try:
                    user_json = json.loads(parsed['user'])
                    debug_info["user_in_init_data"] = {
                        "id": user_json.get('id'),
                        "first_name": user_json.get('first_name'),
                        "username": user_json.get('username'),
                        "language_code": user_json.get('language_code')
                    }
                except:
                    debug_info["user_parse_error"] = True
                    
        except Exception as e:
            debug_info["parse_error"] = str(e)
    
    # Не показываем содержимое init_data в продакшене
    if os.getenv("DEBUG", "false").lower() == "true":
        debug_info["init_data_preview"] = init_data[:200] if init_data else None
    
    # Пробуем верифицировать
    user = verify_telegram_data(init_data)
    debug_info["verification_success"] = user is not None
    
    if user:
        debug_info["verified_user"] = {
            "id": user.get('id'),
            "first_name": user.get('first_name'),
            "username": user.get('username')
        }
    else:
        debug_info["verification_failed_reason"] = "Смотрите логи сервера для деталей"
    
    return jsonify(debug_info)


# ==================== API для задач ====================

@app.route('/api/tasks', methods=['GET'])
def api_get_tasks():
    """Получить все задачи пользователя"""
    init_data = request.headers.get('X-Telegram-Init-Data', '')
    user = verify_telegram_data(init_data)
    
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = user.get('id')
    active_only = request.args.get('active_only', 'true').lower() == 'true'
    tasks = get_tasks_by_user(user_id, active_only)
    
    return jsonify({
        "tasks": [
            {
                "id": task.id,
                "title": task.title,
                "description": task.description,
                "interval_minutes": task.interval_minutes,
                "is_active": task.is_active,
                "next_notification": task.next_notification.isoformat() if task.next_notification else None,
                "created_at": task.created_at.isoformat() if task.created_at else None,
                "updated_at": task.updated_at.isoformat() if task.updated_at else None
            }
            for task in tasks
        ]
    })


@app.route('/api/tasks', methods=['POST'])
def api_create_task():
    """Создать новую задачу"""
    init_data = request.headers.get('X-Telegram-Init-Data', '')
    user = verify_telegram_data(init_data)
    
    if not user:
        print("[API] /api/tasks POST - Ошибка авторизации")
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    if not data:
        print("[API] /api/tasks POST - Нет данных в запросе")
        return jsonify({"error": "No data provided"}), 400
    
    title = data.get('title', '').strip()
    description = data.get('description', '').strip()
    interval_minutes = data.get('interval_minutes', 60)
    
    if not title:
        print("[API] /api/tasks POST - Пустой заголовок")
        return jsonify({"error": "Title is required"}), 400
    
    # Валидация интервала
    try:
        interval_minutes = int(interval_minutes)
        if interval_minutes < 1:
            interval_minutes = 1
        if interval_minutes > 10080:  # Максимум неделя
            interval_minutes = 10080
    except (ValueError, TypeError):
        interval_minutes = 60
    
    user_id = user.get('id')
    print(f"[API] /api/tasks POST - Создание задачи для user_id={user_id}, title='{title[:30]}...'")
    
    try:
        task = create_task(user_id, title, description, interval_minutes)
        print(f"[API] /api/tasks POST - Задача создана, id={task.id}")
        
        # Отправляем начальное уведомление о создании задачи
        message = f"✅ <b>Задача создана!</b>\n\n" \
                  f"📌 <b>{task.title}</b>\n"
        if task.description:
            message += f"📝 {task.description}\n"
        message += f"\n⏰ Напоминания каждые {format_interval(interval_minutes)}"
        send_telegram_message(user_id, message)
        
        return jsonify({
            "id": task.id,
            "title": task.title,
            "description": task.description,
            "interval_minutes": task.interval_minutes,
            "is_active": task.is_active,
            "next_notification": task.next_notification.isoformat() if task.next_notification else None,
            "created_at": task.created_at.isoformat() if task.created_at else None
        }), 201
    except Exception as e:
        print(f"[API] /api/tasks POST - Ошибка создания: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Failed to create task"}), 500


def format_interval(minutes: int) -> str:
    """Форматирование интервала в читаемый вид"""
    if minutes < 60:
        return f"{minutes} мин."
    elif minutes < 1440:
        hours = minutes // 60
        remaining_mins = minutes % 60
        if remaining_mins == 0:
            return f"{hours} ч."
        return f"{hours} ч. {remaining_mins} мин."
    else:
        days = minutes // 1440
        remaining_hours = (minutes % 1440) // 60
        if remaining_hours == 0:
            return f"{days} дн."
        return f"{days} дн. {remaining_hours} ч."


@app.route('/api/tasks/<int:task_id>', methods=['GET'])
def api_get_task(task_id):
    """Получить задачу по ID"""
    init_data = request.headers.get('X-Telegram-Init-Data', '')
    user = verify_telegram_data(init_data)
    
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = user.get('id')
    task = get_task_by_id(task_id, user_id)
    
    if not task:
        return jsonify({"error": "Task not found"}), 404
    
    return jsonify({
        "id": task.id,
        "title": task.title,
        "description": task.description,
        "interval_minutes": task.interval_minutes,
        "is_active": task.is_active,
        "next_notification": task.next_notification.isoformat() if task.next_notification else None,
        "created_at": task.created_at.isoformat() if task.created_at else None,
        "updated_at": task.updated_at.isoformat() if task.updated_at else None
    })


@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
def api_update_task(task_id):
    """Обновить задачу"""
    init_data = request.headers.get('X-Telegram-Init-Data', '')
    user = verify_telegram_data(init_data)
    
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    interval_minutes = data.get('interval_minutes')
    is_active = data.get('is_active')
    
    # Валидация интервала
    if interval_minutes is not None:
        try:
            interval_minutes = int(interval_minutes)
            if interval_minutes < 1:
                interval_minutes = 1
            if interval_minutes > 10080:
                interval_minutes = 10080
        except (ValueError, TypeError):
            interval_minutes = None
    
    user_id = user.get('id')
    task = update_task(task_id, user_id, title, description, interval_minutes, is_active)
    
    if not task:
        return jsonify({"error": "Task not found"}), 404
    
    return jsonify({
        "id": task.id,
        "title": task.title,
        "description": task.description,
        "interval_minutes": task.interval_minutes,
        "is_active": task.is_active,
        "next_notification": task.next_notification.isoformat() if task.next_notification else None,
        "updated_at": task.updated_at.isoformat() if task.updated_at else None
    })


@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
def api_delete_task(task_id):
    """Удалить задачу"""
    init_data = request.headers.get('X-Telegram-Init-Data', '')
    user = verify_telegram_data(init_data)
    
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = user.get('id')
    
    # Получаем задачу для уведомления
    task = get_task_by_id(task_id, user_id)
    if task:
        # Отправляем уведомление об удалении
        message = f"🗑 <b>Задача удалена</b>\n\n📌 {task.title}"
        send_telegram_message(user_id, message)
    
    success = delete_task(task_id, user_id)
    
    if not success:
        return jsonify({"error": "Task not found"}), 404
    
    return jsonify({"success": True})


@app.route('/api/tasks/<int:task_id>/toggle', methods=['POST'])
def api_toggle_task(task_id):
    """Включить/выключить уведомления для задачи"""
    init_data = request.headers.get('X-Telegram-Init-Data', '')
    user = verify_telegram_data(init_data)
    
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = user.get('id')
    task = get_task_by_id(task_id, user_id)
    
    if not task:
        return jsonify({"error": "Task not found"}), 404
    
    # Переключаем статус
    new_status = not task.is_active
    updated_task = update_task(task_id, user_id, is_active=new_status)
    
    # Отправляем уведомление
    status_text = "включены ✅" if new_status else "выключены ⏸"
    message = f"📌 <b>{updated_task.title}</b>\n\nУведомления {status_text}"
    send_telegram_message(user_id, message)
    
    return jsonify({
        "id": updated_task.id,
        "is_active": updated_task.is_active
    })


# Инициализация базы данных при загрузке модуля (работает и с gunicorn)
init_db()

# Запуск планировщика для проверки уведомлений каждую минуту
# Проверяем, не запущен ли уже планировщик (для избежания дублирования при перезагрузке)
if not scheduler.running:
    scheduler.add_job(func=check_and_send_notifications, trigger="interval", minutes=1, id="notification_checker", replace_existing=True)
    scheduler.start()
    print("[INFO] Планировщик уведомлений запущен!")

# Регистрируем остановку планировщика при выходе
atexit.register(lambda: scheduler.shutdown(wait=False) if scheduler.running else None)


if __name__ == '__main__':
    # Запуск сервера в режиме разработки
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=os.getenv("DEBUG", "false").lower() == "true")

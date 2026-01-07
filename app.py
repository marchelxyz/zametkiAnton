import os
import json
import hashlib
import hmac
import uuid
import requests
import atexit
from urllib.parse import unquote, parse_qs
from flask import Flask, request, jsonify, render_template, send_from_directory
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from database import (
    init_db, create_note, get_notes_by_user, get_note_by_id, update_note, delete_note,
    create_task, get_tasks_by_user, get_task_by_id, update_task, delete_task,
    get_tasks_due_for_notification, update_task_next_notification,
    create_attachment, get_attachments_by_note, get_attachment_by_id, delete_attachment,
    get_note_with_attachments
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


def verify_telegram_data(init_data: str) -> dict:
    """
    Проверка данных от Telegram Mini App.
    Возвращает данные пользователя если валидация успешна.
    
    ВАЖНО: init_data от Telegram приходит в URL-encoded формате,
    поэтому значения нужно декодировать перед проверкой подписи.
    """
    # Режим отладки для тестирования вне Telegram
    debug_mode = os.getenv("DEBUG", "false").lower() == "true"
    
    if not BOT_TOKEN:
        # В режиме разработки без токена возвращаем тестовые данные
        print("[DEBUG] BOT_TOKEN не задан, используем тестовые данные")
        return {"id": 123456789, "first_name": "Test", "username": "testuser"}
    
    # Проверяем, что init_data не пустая и содержит корректный формат
    if not init_data or '=' not in init_data:
        if debug_mode:
            # В режиме отладки возвращаем тестовые данные
            print(f"[DEBUG] init_data пустая, используем тестовые данные (DEBUG режим)")
            return {"id": 123456789, "first_name": "Debug", "username": "debuguser"}
        # Более информативное логирование
        init_data_preview = init_data[:50] if init_data else "(пустая)"
        print(f"Ошибка верификации: init_data пустая или некорректная")
        print(f"  - init_data длина: {len(init_data) if init_data else 0}")
        print(f"  - init_data превью: {init_data_preview}")
        print(f"  - Убедитесь, что приложение открыто через Telegram Mini App")
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
        
        # Получаем hash и удаляем его из данных для проверки
        received_hash = parsed_data.pop('hash', '')
        
        if not received_hash:
            print("Ошибка верификации: hash отсутствует в init_data")
            if debug_mode:
                return {"id": 123456789, "first_name": "Debug", "username": "debuguser"}
            return None
        
        # Сортируем по ключу и создаём строку для проверки подписи
        # Формат: key=value\nkey=value\n...
        data_check_string = '\n'.join(f"{k}={v}" for k, v in sorted(parsed_data.items()))
        
        # Создаём секретный ключ согласно документации Telegram:
        # HMAC-SHA256(bot_token, "WebAppData")
        secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        
        # Вычисляем hash для проверки
        calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        
        # Сравниваем hash
        if hmac.compare_digest(calculated_hash, received_hash):
            # Подпись верна, извлекаем данные пользователя
            user_json = parsed_data.get('user', '{}')
            user_data = json.loads(user_json)
            print(f"[OK] Верификация успешна для пользователя: {user_data.get('id')}")
            return user_data
        else:
            print(f"Ошибка верификации: hash не совпадает")
            print(f"  - Получен: {received_hash[:20]}...")
            print(f"  - Вычислен: {calculated_hash[:20]}...")
            if debug_mode:
                # В режиме отладки всё равно возвращаем данные пользователя
                user_json = parsed_data.get('user', '{}')
                try:
                    user_data = json.loads(user_json)
                    print(f"[DEBUG] Возвращаем данные пользователя несмотря на ошибку hash")
                    return user_data
                except:
                    return {"id": 123456789, "first_name": "Debug", "username": "debuguser"}
            return None
            
    except json.JSONDecodeError as e:
        print(f"Ошибка верификации: некорректный JSON в user data: {e}")
        if debug_mode:
            return {"id": 123456789, "first_name": "Debug", "username": "debuguser"}
        return None
    except Exception as e:
        print(f"Ошибка верификации: {e}")
        import traceback
        traceback.print_exc()
        if debug_mode:
            return {"id": 123456789, "first_name": "Debug", "username": "debuguser"}
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
        return jsonify({"error": "Unauthorized"}), 401
    
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
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()
    
    if not title:
        return jsonify({"error": "Title is required"}), 400
    
    user_id = user.get('id')
    note = create_note(user_id, title, content)
    
    return jsonify({
        "id": note.id,
        "title": note.title,
        "content": note.content,
        "created_at": note.created_at.isoformat() if note.created_at else None
    }), 201


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
    
    # Удаляем файлы вложений перед удалением заметки
    attachments = get_attachments_by_note(note_id)
    for att in attachments:
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], att.stored_filename)
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"[ERROR] Ошибка удаления файла {att.stored_filename}: {e}")
    
    success = delete_note(note_id, user_id)
    
    if not success:
        return jsonify({"error": "Note not found"}), 404
    
    return jsonify({"success": True})


# ==================== API для вложений ====================

@app.route('/api/notes/<int:note_id>/attachments', methods=['POST'])
def api_upload_attachment(note_id):
    """Загрузить вложение к заметке"""
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
    stored_filename = generate_stored_filename(original_filename)
    file_type = get_file_type(original_filename)
    
    # Сохраняем файл
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
    file.save(file_path)
    
    # Получаем размер файла
    file_size = os.path.getsize(file_path)
    
    # Определяем MIME тип
    mime_type = file.content_type
    
    # Создаём запись в БД
    attachment = create_attachment(
        note_id=note_id,
        filename=original_filename,
        stored_filename=stored_filename,
        file_type=file_type,
        mime_type=mime_type,
        file_size=file_size
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
    """Скачать вложение"""
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
    
    # Отправляем файл
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        attachment.stored_filename,
        download_name=attachment.filename,
        as_attachment=False
    )


@app.route('/api/attachments/<int:attachment_id>', methods=['DELETE'])
def api_delete_attachment(attachment_id):
    """Удалить вложение"""
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
    
    # Удаляем файл
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], attachment.stored_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        print(f"[ERROR] Ошибка удаления файла: {e}")
    
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
    
    # Не показываем содержимое init_data в продакшене
    if os.getenv("DEBUG", "false").lower() == "true":
        debug_info["init_data_preview"] = init_data[:200] if init_data else None
    
    # Пробуем верифицировать
    user = verify_telegram_data(init_data)
    debug_info["verification_success"] = user is not None
    
    if user:
        debug_info["user_id"] = user.get('id')
        debug_info["user_name"] = user.get('first_name')
        debug_info["user_username"] = user.get('username')
    
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
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    title = data.get('title', '').strip()
    description = data.get('description', '').strip()
    interval_minutes = data.get('interval_minutes', 60)
    
    if not title:
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
    task = create_task(user_id, title, description, interval_minutes)
    
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

import os
import json
import hashlib
import hmac
import requests
import atexit
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from database import (
    init_db, create_note, get_notes_by_user, get_note_by_id, update_note, delete_note,
    create_task, get_tasks_by_user, get_task_by_id, update_task, delete_task,
    get_tasks_due_for_notification, update_task_next_notification
)

# Загружаем переменные окружения
load_dotenv()

app = Flask(__name__)

# Получаем токен бота из переменных окружения
BOT_TOKEN = os.getenv("BOT_TOKEN", "")

# Планировщик для периодических задач
scheduler = BackgroundScheduler()


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
    """
    if not BOT_TOKEN:
        # В режиме разработки без токена возвращаем тестовые данные
        return {"id": 123456789, "first_name": "Test", "username": "testuser"}
    
    # Проверяем, что init_data не пустая и содержит корректный формат
    if not init_data or '=' not in init_data:
        print(f"Ошибка верификации: init_data пустая или некорректная")
        return None
    
    try:
        # Парсим init_data
        parsed_data = dict(x.split('=', 1) for x in init_data.split('&') if '=' in x)
        
        # Получаем hash и удаляем его из данных
        received_hash = parsed_data.pop('hash', '')
        
        # Сортируем и создаём строку для проверки
        data_check_string = '\n'.join(f"{k}={v}" for k, v in sorted(parsed_data.items()))
        
        # Создаём секретный ключ
        secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        
        # Вычисляем hash
        calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        
        # Проверяем hash
        if calculated_hash == received_hash:
            user_data = json.loads(parsed_data.get('user', '{}'))
            return user_data
        return None
    except Exception as e:
        print(f"Ошибка верификации: {e}")
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
    
    return jsonify({
        "notes": [
            {
                "id": note.id,
                "title": note.title,
                "content": note.content,
                "created_at": note.created_at.isoformat() if note.created_at else None,
                "updated_at": note.updated_at.isoformat() if note.updated_at else None
            }
            for note in notes
        ]
    })


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
    note = get_note_by_id(note_id, user_id)
    
    if not note:
        return jsonify({"error": "Note not found"}), 404
    
    return jsonify({
        "id": note.id,
        "title": note.title,
        "content": note.content,
        "created_at": note.created_at.isoformat() if note.created_at else None,
        "updated_at": note.updated_at.isoformat() if note.updated_at else None
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
    success = delete_note(note_id, user_id)
    
    if not success:
        return jsonify({"error": "Note not found"}), 404
    
    return jsonify({"success": True})


@app.route('/health')
def health():
    """Health check для Railway"""
    return jsonify({"status": "ok"})


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

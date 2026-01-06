import os
import json
import hashlib
import hmac
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
from database import init_db, create_note, get_notes_by_user, get_note_by_id, update_note, delete_note

# Загружаем переменные окружения
load_dotenv()

app = Flask(__name__)

# Получаем токен бота из переменных окружения
BOT_TOKEN = os.getenv("BOT_TOKEN", "")


def verify_telegram_data(init_data: str) -> dict:
    """
    Проверка данных от Telegram Mini App.
    Возвращает данные пользователя если валидация успешна.
    """
    if not BOT_TOKEN:
        # В режиме разработки без токена возвращаем тестовые данные
        return {"id": 123456789, "first_name": "Test", "username": "testuser"}
    
    try:
        # Парсим init_data
        parsed_data = dict(x.split('=') for x in init_data.split('&'))
        
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


if __name__ == '__main__':
    # Инициализация базы данных при запуске
    init_db()
    
    # Запуск сервера
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=os.getenv("DEBUG", "false").lower() == "true")

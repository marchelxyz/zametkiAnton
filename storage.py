"""
Модуль для работы с Google Cloud Storage.
Используется для хранения вложений (фото и документов) заметок.
"""
import os
import uuid
import base64
import json
import tempfile
from typing import Optional, Tuple

# Загружаем переменные окружения
from dotenv import load_dotenv
load_dotenv()

# Конфигурация Google Cloud Storage
GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME", "")
GCS_CREDENTIALS_BASE64 = os.getenv("GCS_CREDENTIALS_BASE64", "")

# Флаг доступности GCS
_gcs_client = None
_gcs_bucket = None
_gcs_available = False


def _init_gcs():
    """Инициализация клиента Google Cloud Storage"""
    global _gcs_client, _gcs_bucket, _gcs_available
    
    if _gcs_client is not None:
        return _gcs_available
    
    if not GCS_BUCKET_NAME:
        print("[GCS] GCS_BUCKET_NAME не задан, используем локальное хранение в БД")
        _gcs_available = False
        return False
    
    try:
        from google.cloud import storage
        
        # Пытаемся получить credentials из base64-encoded JSON
        if GCS_CREDENTIALS_BASE64:
            try:
                credentials_json = base64.b64decode(GCS_CREDENTIALS_BASE64).decode('utf-8')
                credentials_dict = json.loads(credentials_json)
                
                # Создаём временный файл с credentials
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                    json.dump(credentials_dict, f)
                    credentials_path = f.name
                
                _gcs_client = storage.Client.from_service_account_json(credentials_path)
                
                # Удаляем временный файл
                try:
                    os.unlink(credentials_path)
                except:
                    pass
                    
                print(f"[GCS] Клиент инициализирован с credentials из GCS_CREDENTIALS_BASE64")
            except Exception as e:
                print(f"[GCS] Ошибка декодирования GCS_CREDENTIALS_BASE64: {e}")
                _gcs_client = storage.Client()
        else:
            # Используем default credentials (GOOGLE_APPLICATION_CREDENTIALS или ADC)
            _gcs_client = storage.Client()
            print("[GCS] Клиент инициализирован с default credentials")
        
        _gcs_bucket = _gcs_client.bucket(GCS_BUCKET_NAME)
        
        # Проверяем доступность бакета
        if not _gcs_bucket.exists():
            print(f"[GCS] ВНИМАНИЕ: Бакет '{GCS_BUCKET_NAME}' не существует!")
            _gcs_available = False
            return False
        
        _gcs_available = True
        print(f"[GCS] Успешно подключено к бакету: {GCS_BUCKET_NAME}")
        return True
        
    except ImportError:
        print("[GCS] Библиотека google-cloud-storage не установлена")
        _gcs_available = False
        return False
    except Exception as e:
        print(f"[GCS] Ошибка инициализации: {e}")
        _gcs_available = False
        return False


def is_gcs_available() -> bool:
    """Проверить, доступно ли хранилище GCS"""
    _init_gcs()
    return _gcs_available


def generate_gcs_path(user_id: int, note_id: int, filename: str) -> str:
    """
    Сгенерировать уникальный путь для файла в GCS.
    Формат: users/{user_id}/notes/{note_id}/{uuid}_{filename}
    """
    # Получаем расширение файла
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    # Генерируем уникальный идентификатор
    unique_id = uuid.uuid4().hex[:12]
    
    # Создаём безопасное имя файла
    safe_filename = f"{unique_id}"
    if ext:
        safe_filename = f"{safe_filename}.{ext}"
    
    return f"users/{user_id}/notes/{note_id}/{safe_filename}"


def upload_to_gcs(
    file_data: bytes,
    gcs_path: str,
    content_type: str = 'application/octet-stream'
) -> Tuple[bool, Optional[str]]:
    """
    Загрузить файл в Google Cloud Storage.
    
    Args:
        file_data: Бинарные данные файла
        gcs_path: Путь в бакете (например, users/123/notes/456/abc.jpg)
        content_type: MIME-тип файла
    
    Returns:
        Tuple[success: bool, public_url или error_message]
    """
    if not is_gcs_available():
        return False, "GCS недоступен"
    
    try:
        blob = _gcs_bucket.blob(gcs_path)
        
        # Загружаем файл
        blob.upload_from_string(
            file_data,
            content_type=content_type
        )
        
        # Возвращаем путь (не публичный URL, т.к. доступ через наш API)
        print(f"[GCS] Файл загружен: {gcs_path}")
        return True, gcs_path
        
    except Exception as e:
        print(f"[GCS] Ошибка загрузки файла: {e}")
        return False, str(e)


def download_from_gcs(gcs_path: str) -> Tuple[bool, Optional[bytes], Optional[str]]:
    """
    Скачать файл из Google Cloud Storage.
    
    Args:
        gcs_path: Путь к файлу в бакете
    
    Returns:
        Tuple[success: bool, file_data или None, content_type или error_message]
    """
    if not is_gcs_available():
        return False, None, "GCS недоступен"
    
    try:
        blob = _gcs_bucket.blob(gcs_path)
        
        # Проверяем существование
        if not blob.exists():
            return False, None, "Файл не найден в GCS"
        
        # Скачиваем файл
        file_data = blob.download_as_bytes()
        content_type = blob.content_type or 'application/octet-stream'
        
        return True, file_data, content_type
        
    except Exception as e:
        print(f"[GCS] Ошибка скачивания файла: {e}")
        return False, None, str(e)


def delete_from_gcs(gcs_path: str) -> bool:
    """
    Удалить файл из Google Cloud Storage.
    
    Args:
        gcs_path: Путь к файлу в бакете
    
    Returns:
        True если файл удалён или не существовал, False при ошибке
    """
    if not is_gcs_available():
        return True  # Если GCS недоступен, считаем удаление успешным
    
    try:
        blob = _gcs_bucket.blob(gcs_path)
        
        # Удаляем только если существует
        if blob.exists():
            blob.delete()
            print(f"[GCS] Файл удалён: {gcs_path}")
        
        return True
        
    except Exception as e:
        print(f"[GCS] Ошибка удаления файла: {e}")
        return False


def delete_note_files(user_id: int, note_id: int) -> bool:
    """
    Удалить все файлы заметки из GCS.
    
    Args:
        user_id: ID пользователя
        note_id: ID заметки
    
    Returns:
        True если успешно, False при ошибке
    """
    if not is_gcs_available():
        return True
    
    try:
        prefix = f"users/{user_id}/notes/{note_id}/"
        blobs = _gcs_bucket.list_blobs(prefix=prefix)
        
        count = 0
        for blob in blobs:
            blob.delete()
            count += 1
        
        if count > 0:
            print(f"[GCS] Удалено {count} файлов для заметки {note_id}")
        
        return True
        
    except Exception as e:
        print(f"[GCS] Ошибка удаления файлов заметки: {e}")
        return False


# GCS инициализируется лениво при первом вызове is_gcs_available()
# Не вызываем _init_gcs() при импорте модуля, чтобы избежать блокировки при gunicorn preload

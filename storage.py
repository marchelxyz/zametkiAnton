"""
Модуль для работы с облачными хранилищами (Google Cloud Storage и Yandex Cloud S3).
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

# Тип хранилища: "gcs", "s3" или пусто (используется БД)
STORAGE_TYPE = os.getenv("STORAGE_TYPE", "").lower()

# Конфигурация Google Cloud Storage
GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME", "")
GCS_CREDENTIALS_BASE64 = os.getenv("GCS_CREDENTIALS_BASE64", "")

# Конфигурация Yandex Cloud S3
YC_S3_BUCKET_NAME = os.getenv("YC_S3_BUCKET_NAME", "")
YC_S3_ACCESS_KEY_ID = os.getenv("YC_S3_ACCESS_KEY_ID", "")
YC_S3_SECRET_ACCESS_KEY = os.getenv("YC_S3_SECRET_ACCESS_KEY", "")
YC_S3_ENDPOINT_URL = os.getenv("YC_S3_ENDPOINT_URL", "https://storage.yandexcloud.net")
YC_S3_REGION = os.getenv("YC_S3_REGION", "ru-central1")

# Флаги доступности хранилищ
_gcs_client = None
_gcs_bucket = None
_gcs_available = False

_s3_client = None
_s3_bucket_name = None
_s3_available = False


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


def _init_s3():
    """Инициализация клиента Yandex Cloud S3"""
    global _s3_client, _s3_bucket_name, _s3_available
    
    if _s3_client is not None:
        return _s3_available
    
    if not YC_S3_BUCKET_NAME or not YC_S3_ACCESS_KEY_ID or not YC_S3_SECRET_ACCESS_KEY:
        print("[S3] YC_S3_BUCKET_NAME, YC_S3_ACCESS_KEY_ID или YC_S3_SECRET_ACCESS_KEY не заданы, используем локальное хранение в БД")
        _s3_available = False
        return False
    
    try:
        import boto3
        from botocore.exceptions import ClientError
        
        # Создаём клиент S3 для Yandex Cloud
        _s3_client = boto3.client(
            's3',
            endpoint_url=YC_S3_ENDPOINT_URL,
            aws_access_key_id=YC_S3_ACCESS_KEY_ID,
            aws_secret_access_key=YC_S3_SECRET_ACCESS_KEY,
            region_name=YC_S3_REGION
        )
        
        _s3_bucket_name = YC_S3_BUCKET_NAME
        
        # Проверяем доступность бакета
        try:
            _s3_client.head_bucket(Bucket=YC_S3_BUCKET_NAME)
            _s3_available = True
            print(f"[S3] Успешно подключено к бакету: {YC_S3_BUCKET_NAME}")
            return True
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == '404':
                print(f"[S3] ВНИМАНИЕ: Бакет '{YC_S3_BUCKET_NAME}' не существует!")
            else:
                print(f"[S3] Ошибка доступа к бакету: {e}")
            _s3_available = False
            return False
        
    except ImportError:
        print("[S3] Библиотека boto3 не установлена")
        _s3_available = False
        return False
    except Exception as e:
        print(f"[S3] Ошибка инициализации: {e}")
        _s3_available = False
        return False


def is_storage_available() -> bool:
    """Проверить, доступно ли облачное хранилище (GCS или S3)"""
    if STORAGE_TYPE == "gcs":
        _init_gcs()
        return _gcs_available
    elif STORAGE_TYPE == "s3":
        _init_s3()
        return _s3_available
    else:
        # Если тип не задан, проверяем оба хранилища (для обратной совместимости)
        _init_gcs()
        _init_s3()
        return _gcs_available or _s3_available


def is_gcs_available() -> bool:
    """Проверить, доступно ли хранилище GCS (для обратной совместимости)"""
    _init_gcs()
    return _gcs_available


def generate_storage_path(user_id: int, note_id: int, filename: str) -> str:
    """
    Сгенерировать уникальный путь для файла в облачном хранилище.
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


def generate_gcs_path(user_id: int, note_id: int, filename: str) -> str:
    """Сгенерировать путь для файла в GCS (для обратной совместимости)"""
    return generate_storage_path(user_id, note_id, filename)


def upload_to_storage(
    file_data: bytes,
    storage_path: str,
    content_type: str = 'application/octet-stream'
) -> Tuple[bool, Optional[str]]:
    """
    Загрузить файл в облачное хранилище (GCS или S3).
    
    Args:
        file_data: Бинарные данные файла
        storage_path: Путь в хранилище (например, users/123/notes/456/abc.jpg)
        content_type: MIME-тип файла
    
    Returns:
        Tuple[success: bool, storage_path или error_message]
    """
    # Определяем тип хранилища
    if STORAGE_TYPE == "s3":
        return _upload_to_s3(file_data, storage_path, content_type)
    elif STORAGE_TYPE == "gcs":
        return _upload_to_gcs(file_data, storage_path, content_type)
    else:
        # Автоопределение: пробуем S3, потом GCS
        if _s3_available or YC_S3_BUCKET_NAME:
            _init_s3()
            if _s3_available:
                return _upload_to_s3(file_data, storage_path, content_type)
        
        if _gcs_available or GCS_BUCKET_NAME:
            _init_gcs()
            if _gcs_available:
                return _upload_to_gcs(file_data, storage_path, content_type)
        
        return False, "Облачное хранилище недоступно"


def _upload_to_gcs(
    file_data: bytes,
    gcs_path: str,
    content_type: str = 'application/octet-stream'
) -> Tuple[bool, Optional[str]]:
    """Загрузить файл в Google Cloud Storage"""
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


def _upload_to_s3(
    file_data: bytes,
    s3_path: str,
    content_type: str = 'application/octet-stream'
) -> Tuple[bool, Optional[str]]:
    """Загрузить файл в Yandex Cloud S3"""
    if not _s3_available:
        return False, "S3 недоступен"
    
    try:
        _s3_client.put_object(
            Bucket=_s3_bucket_name,
            Key=s3_path,
            Body=file_data,
            ContentType=content_type
        )
        
        print(f"[S3] Файл загружен: {s3_path}")
        return True, s3_path
        
    except Exception as e:
        print(f"[S3] Ошибка загрузки файла: {e}")
        return False, str(e)


def upload_to_gcs(
    file_data: bytes,
    gcs_path: str,
    content_type: str = 'application/octet-stream'
) -> Tuple[bool, Optional[str]]:
    """Загрузить файл в Google Cloud Storage (для обратной совместимости)"""
    return _upload_to_gcs(file_data, gcs_path, content_type)


def download_from_storage(storage_path: str) -> Tuple[bool, Optional[bytes], Optional[str]]:
    """
    Скачать файл из облачного хранилища (GCS или S3).
    
    Args:
        storage_path: Путь к файлу в хранилище
    
    Returns:
        Tuple[success: bool, file_data или None, content_type или error_message]
    """
    # Определяем тип хранилища по пути или настройкам
    # Если путь начинается с известного префикса или есть явная настройка
    if STORAGE_TYPE == "s3":
        return _download_from_s3(storage_path)
    elif STORAGE_TYPE == "gcs":
        return _download_from_gcs(storage_path)
    else:
        # Автоопределение: пробуем оба хранилища
        # Сначала проверяем S3
        if _s3_available or YC_S3_BUCKET_NAME:
            _init_s3()
            if _s3_available:
                result = _download_from_s3(storage_path)
                if result[0]:  # Если успешно, возвращаем результат
                    return result
        
        # Пробуем GCS
        if _gcs_available or GCS_BUCKET_NAME:
            _init_gcs()
            if _gcs_available:
                return _download_from_gcs(storage_path)
        
        return False, None, "Облачное хранилище недоступно"


def _download_from_gcs(gcs_path: str) -> Tuple[bool, Optional[bytes], Optional[str]]:
    """Скачать файл из Google Cloud Storage"""
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


def _download_from_s3(s3_path: str) -> Tuple[bool, Optional[bytes], Optional[str]]:
    """Скачать файл из Yandex Cloud S3"""
    if not _s3_available:
        return False, None, "S3 недоступен"
    
    try:
        from botocore.exceptions import ClientError
        
        response = _s3_client.get_object(
            Bucket=_s3_bucket_name,
            Key=s3_path
        )
        
        file_data = response['Body'].read()
        content_type = response.get('ContentType', 'application/octet-stream')
        
        return True, file_data, content_type
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'NoSuchKey':
            return False, None, "Файл не найден в S3"
        print(f"[S3] Ошибка скачивания файла: {e}")
        return False, None, str(e)
    except Exception as e:
        print(f"[S3] Ошибка скачивания файла: {e}")
        return False, None, str(e)


def download_from_gcs(gcs_path: str) -> Tuple[bool, Optional[bytes], Optional[str]]:
    """Скачать файл из Google Cloud Storage (для обратной совместимости)"""
    return _download_from_gcs(gcs_path)


def delete_from_storage(storage_path: str) -> bool:
    """
    Удалить файл из облачного хранилища (GCS или S3).
    
    Args:
        storage_path: Путь к файлу в хранилище
    
    Returns:
        True если файл удалён или не существовал, False при ошибке
    """
    if STORAGE_TYPE == "s3":
        return _delete_from_s3(storage_path)
    elif STORAGE_TYPE == "gcs":
        return _delete_from_gcs(storage_path)
    else:
        # Автоопределение: пробуем оба хранилища
        success = True
        
        if _s3_available or YC_S3_BUCKET_NAME:
            _init_s3()
            if _s3_available:
                success = _delete_from_s3(storage_path) and success
        
        if _gcs_available or GCS_BUCKET_NAME:
            _init_gcs()
            if _gcs_available:
                success = _delete_from_gcs(storage_path) and success
        
        return success


def _delete_from_gcs(gcs_path: str) -> bool:
    """Удалить файл из Google Cloud Storage"""
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


def _delete_from_s3(s3_path: str) -> bool:
    """Удалить файл из Yandex Cloud S3"""
    if not _s3_available:
        return True  # Если S3 недоступен, считаем удаление успешным
    
    try:
        from botocore.exceptions import ClientError
        
        _s3_client.delete_object(
            Bucket=_s3_bucket_name,
            Key=s3_path
        )
        
        print(f"[S3] Файл удалён: {s3_path}")
        return True
        
    except ClientError as e:
        # Если файл не найден, считаем удаление успешным
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'NoSuchKey':
            print(f"[S3] Файл не найден (уже удалён): {s3_path}")
            return True
        print(f"[S3] Ошибка удаления файла: {e}")
        return False
    except Exception as e:
        print(f"[S3] Ошибка удаления файла: {e}")
        return False


def delete_from_gcs(gcs_path: str) -> bool:
    """Удалить файл из Google Cloud Storage (для обратной совместимости)"""
    return _delete_from_gcs(gcs_path)


def delete_note_files(user_id: int, note_id: int) -> bool:
    """
    Удалить все файлы заметки из облачного хранилища (GCS или S3).
    
    Args:
        user_id: ID пользователя
        note_id: ID заметки
    
    Returns:
        True если успешно, False при ошибке
    """
    prefix = f"users/{user_id}/notes/{note_id}/"
    success = True
    
    if STORAGE_TYPE == "s3":
        return _delete_note_files_from_s3(prefix)
    elif STORAGE_TYPE == "gcs":
        return _delete_note_files_from_gcs(prefix)
    else:
        # Автоопределение: пробуем оба хранилища
        if _s3_available or YC_S3_BUCKET_NAME:
            _init_s3()
            if _s3_available:
                success = _delete_note_files_from_s3(prefix) and success
        
        if _gcs_available or GCS_BUCKET_NAME:
            _init_gcs()
            if _gcs_available:
                success = _delete_note_files_from_gcs(prefix) and success
        
        return success


def _delete_note_files_from_gcs(prefix: str) -> bool:
    """Удалить все файлы заметки из Google Cloud Storage"""
    if not is_gcs_available():
        return True
    
    try:
        blobs = _gcs_bucket.list_blobs(prefix=prefix)
        
        count = 0
        for blob in blobs:
            blob.delete()
            count += 1
        
        if count > 0:
            print(f"[GCS] Удалено {count} файлов для префикса {prefix}")
        
        return True
        
    except Exception as e:
        print(f"[GCS] Ошибка удаления файлов заметки: {e}")
        return False


def _delete_note_files_from_s3(prefix: str) -> bool:
    """Удалить все файлы заметки из Yandex Cloud S3"""
    if not _s3_available:
        return True
    
    try:
        from botocore.exceptions import ClientError
        
        # Получаем список объектов с указанным префиксом
        paginator = _s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=_s3_bucket_name, Prefix=prefix)
        
        count = 0
        for page in pages:
            if 'Contents' in page:
                for obj in page['Contents']:
                    _s3_client.delete_object(
                        Bucket=_s3_bucket_name,
                        Key=obj['Key']
                    )
                    count += 1
        
        if count > 0:
            print(f"[S3] Удалено {count} файлов для префикса {prefix}")
        
        return True
        
    except Exception as e:
        print(f"[S3] Ошибка удаления файлов заметки: {e}")
        return False


# GCS инициализируется лениво при первом вызове is_gcs_available()
# Не вызываем _init_gcs() при импорте модуля, чтобы избежать блокировки при gunicorn preload

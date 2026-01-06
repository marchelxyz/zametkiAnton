import os
from sqlalchemy import create_engine, Column, Integer, BigInteger, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime, timezone, timedelta

# Московский часовой пояс (UTC+3)
MOSCOW_TZ = timezone(timedelta(hours=3))


def moscow_now():
    """Получить текущее время в московском часовом поясе"""
    return datetime.now(MOSCOW_TZ).replace(tzinfo=None)

# Получаем DATABASE_URL из переменных окружения Railway
# Если не задана - используем SQLite для локальной разработки
DATABASE_URL = os.getenv("DATABASE_URL", "")

if DATABASE_URL:
    # Railway использует postgres:// но SQLAlchemy требует postgresql://
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    print(f"[DB] Используем PostgreSQL")
else:
    # Локальная разработка - SQLite
    DATABASE_URL = "sqlite:///./notes_app.db"
    print(f"[DB] DATABASE_URL не задана, используем SQLite: {DATABASE_URL}")

# Создаём движок базы данных
# check_same_thread=False нужен для SQLite при многопоточном доступе
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(DATABASE_URL, connect_args=connect_args)

# Создаём базовый класс для моделей
Base = declarative_base()

# Создаём сессию
# expire_on_commit=False важен для того, чтобы объекты оставались доступными после закрытия сессии
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, expire_on_commit=False)


class Note(Base):
    """Модель заметки"""
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(BigInteger, index=True, nullable=False)  # Telegram user ID
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=True)
    created_at = Column(DateTime, default=moscow_now)
    updated_at = Column(DateTime, default=moscow_now, onupdate=moscow_now)
    
    # Связь с вложениями
    attachments = relationship("Attachment", back_populates="note", cascade="all, delete-orphan")


class Attachment(Base):
    """Модель вложения (фото/файл)"""
    __tablename__ = "attachments"

    id = Column(Integer, primary_key=True, index=True)
    note_id = Column(Integer, ForeignKey("notes.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)  # Оригинальное имя файла
    stored_filename = Column(String(255), nullable=False)  # Имя файла в хранилище
    file_type = Column(String(50), nullable=False)  # Тип файла (image/document)
    mime_type = Column(String(100), nullable=True)  # MIME тип
    file_size = Column(Integer, nullable=True)  # Размер в байтах
    created_at = Column(DateTime, default=moscow_now)
    
    # Связь с заметкой
    note = relationship("Note", back_populates="attachments")


class Task(Base):
    """Модель задачи с уведомлениями"""
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(BigInteger, index=True, nullable=False)  # Telegram user ID
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    interval_minutes = Column(Integer, nullable=False, default=60)  # Интервал в минутах
    is_active = Column(Boolean, default=True)  # Активна ли задача
    next_notification = Column(DateTime, nullable=True)  # Время следующего уведомления
    created_at = Column(DateTime, default=moscow_now)
    updated_at = Column(DateTime, default=moscow_now, onupdate=moscow_now)


def init_db():
    """Инициализация базы данных - создание таблиц"""
    Base.metadata.create_all(bind=engine)
    print("База данных инициализирована!")


def get_db():
    """Получение сессии базы данных"""
    db = SessionLocal()
    try:
        return db
    finally:
        pass


# Функции для работы с заметками
def create_note(user_id: int, title: str, content: str = "") -> Note:
    """Создать новую заметку"""
    db = SessionLocal()
    try:
        note = Note(user_id=user_id, title=title, content=content)
        db.add(note)
        db.commit()
        db.refresh(note)
        db.expunge(note)  # Отвязываем объект от сессии
        return note
    finally:
        db.close()


def get_notes_by_user(user_id: int) -> list:
    """Получить все заметки пользователя"""
    db = SessionLocal()
    try:
        notes = db.query(Note).filter(Note.user_id == user_id).order_by(Note.created_at.desc()).all()
        for note in notes:
            db.expunge(note)  # Отвязываем объекты от сессии
        return notes
    finally:
        db.close()


def get_note_by_id(note_id: int, user_id: int) -> Note:
    """Получить заметку по ID"""
    db = SessionLocal()
    try:
        note = db.query(Note).filter(Note.id == note_id, Note.user_id == user_id).first()
        if note:
            db.expunge(note)  # Отвязываем объект от сессии
        return note
    finally:
        db.close()


def update_note(note_id: int, user_id: int, title: str = None, content: str = None) -> Note:
    """Обновить заметку"""
    db = SessionLocal()
    try:
        note = db.query(Note).filter(Note.id == note_id, Note.user_id == user_id).first()
        if note:
            if title is not None:
                note.title = title
            if content is not None:
                note.content = content
            note.updated_at = moscow_now()
            db.commit()
            db.refresh(note)
            db.expunge(note)  # Отвязываем объект от сессии
        return note
    finally:
        db.close()


def delete_note(note_id: int, user_id: int) -> bool:
    """Удалить заметку"""
    db = SessionLocal()
    try:
        note = db.query(Note).filter(Note.id == note_id, Note.user_id == user_id).first()
        if note:
            db.delete(note)
            db.commit()
            return True
        return False
    finally:
        db.close()


# Функции для работы с задачами
def create_task(user_id: int, title: str, description: str = "", interval_minutes: int = 60) -> Task:
    """Создать новую задачу"""
    db = SessionLocal()
    try:
        next_notification = moscow_now() + timedelta(minutes=interval_minutes)
        task = Task(
            user_id=user_id,
            title=title,
            description=description,
            interval_minutes=interval_minutes,
            is_active=True,
            next_notification=next_notification
        )
        db.add(task)
        db.commit()
        db.refresh(task)
        db.expunge(task)  # Отвязываем объект от сессии
        return task
    finally:
        db.close()


def get_tasks_by_user(user_id: int, active_only: bool = True) -> list:
    """Получить все задачи пользователя"""
    db = SessionLocal()
    try:
        query = db.query(Task).filter(Task.user_id == user_id)
        if active_only:
            query = query.filter(Task.is_active == True)
        tasks = query.order_by(Task.created_at.desc()).all()
        for task in tasks:
            db.expunge(task)  # Отвязываем объекты от сессии
        return tasks
    finally:
        db.close()


def get_task_by_id(task_id: int, user_id: int) -> Task:
    """Получить задачу по ID"""
    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.id == task_id, Task.user_id == user_id).first()
        if task:
            db.expunge(task)  # Отвязываем объект от сессии
        return task
    finally:
        db.close()


def update_task(task_id: int, user_id: int, title: str = None, description: str = None, 
                interval_minutes: int = None, is_active: bool = None) -> Task:
    """Обновить задачу"""
    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.id == task_id, Task.user_id == user_id).first()
        if task:
            if title is not None:
                task.title = title
            if description is not None:
                task.description = description
            if interval_minutes is not None:
                task.interval_minutes = interval_minutes
                # Пересчитываем следующее уведомление
                task.next_notification = moscow_now() + timedelta(minutes=interval_minutes)
            if is_active is not None:
                task.is_active = is_active
            task.updated_at = moscow_now()
            db.commit()
            db.refresh(task)
            db.expunge(task)  # Отвязываем объект от сессии
        return task
    finally:
        db.close()


def delete_task(task_id: int, user_id: int) -> bool:
    """Удалить задачу"""
    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.id == task_id, Task.user_id == user_id).first()
        if task:
            db.delete(task)
            db.commit()
            return True
        return False
    finally:
        db.close()


def get_tasks_due_for_notification() -> list:
    """Получить задачи, для которых пора отправить уведомление"""
    db = SessionLocal()
    try:
        tasks = db.query(Task).filter(
            Task.is_active == True,
            Task.next_notification <= moscow_now()
        ).all()
        for task in tasks:
            db.expunge(task)  # Отвязываем объекты от сессии
        return tasks
    finally:
        db.close()


def update_task_next_notification(task_id: int) -> Task:
    """Обновить время следующего уведомления для задачи"""
    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.id == task_id).first()
        if task:
            task.next_notification = moscow_now() + timedelta(minutes=task.interval_minutes)
            db.commit()
            db.refresh(task)
            db.expunge(task)  # Отвязываем объект от сессии
        return task
    finally:
        db.close()


# Функции для работы с вложениями
def create_attachment(note_id: int, filename: str, stored_filename: str, 
                      file_type: str, mime_type: str = None, file_size: int = None) -> Attachment:
    """Создать новое вложение"""
    db = SessionLocal()
    try:
        attachment = Attachment(
            note_id=note_id,
            filename=filename,
            stored_filename=stored_filename,
            file_type=file_type,
            mime_type=mime_type,
            file_size=file_size
        )
        db.add(attachment)
        db.commit()
        db.refresh(attachment)
        db.expunge(attachment)
        return attachment
    finally:
        db.close()


def get_attachments_by_note(note_id: int) -> list:
    """Получить все вложения заметки"""
    db = SessionLocal()
    try:
        attachments = db.query(Attachment).filter(Attachment.note_id == note_id).order_by(Attachment.created_at.asc()).all()
        for attachment in attachments:
            db.expunge(attachment)
        return attachments
    finally:
        db.close()


def get_attachment_by_id(attachment_id: int) -> Attachment:
    """Получить вложение по ID"""
    db = SessionLocal()
    try:
        attachment = db.query(Attachment).filter(Attachment.id == attachment_id).first()
        if attachment:
            db.expunge(attachment)
        return attachment
    finally:
        db.close()


def delete_attachment(attachment_id: int) -> Attachment:
    """Удалить вложение и вернуть его данные для удаления файла"""
    db = SessionLocal()
    try:
        attachment = db.query(Attachment).filter(Attachment.id == attachment_id).first()
        if attachment:
            db.expunge(attachment)
            db.query(Attachment).filter(Attachment.id == attachment_id).delete()
            db.commit()
        return attachment
    finally:
        db.close()


def get_note_with_attachments(note_id: int, user_id: int):
    """Получить заметку с вложениями"""
    db = SessionLocal()
    try:
        note = db.query(Note).filter(Note.id == note_id, Note.user_id == user_id).first()
        if note:
            attachments = db.query(Attachment).filter(Attachment.note_id == note_id).order_by(Attachment.created_at.asc()).all()
            db.expunge(note)
            for att in attachments:
                db.expunge(att)
            return note, attachments
        return None, []
    finally:
        db.close()

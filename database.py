import os
from sqlalchemy import create_engine, Column, Integer, BigInteger, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# Получаем DATABASE_URL из переменных окружения Railway
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://localhost:5432/notes_db")

# Railway использует postgres:// но SQLAlchemy требует postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Создаём движок базы данных
engine = create_engine(DATABASE_URL)

# Создаём базовый класс для моделей
Base = declarative_base()

# Создаём сессию
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Note(Base):
    """Модель заметки"""
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(BigInteger, index=True, nullable=False)  # Telegram user ID
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


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
        return note
    finally:
        db.close()


def get_notes_by_user(user_id: int) -> list:
    """Получить все заметки пользователя"""
    db = SessionLocal()
    try:
        notes = db.query(Note).filter(Note.user_id == user_id).order_by(Note.created_at.desc()).all()
        return notes
    finally:
        db.close()


def get_note_by_id(note_id: int, user_id: int) -> Note:
    """Получить заметку по ID"""
    db = SessionLocal()
    try:
        note = db.query(Note).filter(Note.id == note_id, Note.user_id == user_id).first()
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
            note.updated_at = datetime.utcnow()
            db.commit()
            db.refresh(note)
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

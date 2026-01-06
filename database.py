import os
from sqlalchemy import create_engine, Column, Integer, BigInteger, String, Text, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# Получаем DATABASE_URL из переменных окружения Railway
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://localhost:5432/notes_db")

# Railway использует postgres:// но SQLAlchemy требует postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Создаём движок базы данных
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

# Создаём базовый класс для моделей
Base = declarative_base()

# Создаём сессию с expire_on_commit=False чтобы объекты оставались доступными после commit
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, expire_on_commit=False)


class Note(Base):
    """Модель заметки"""
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(BigInteger, index=True, nullable=False)  # Telegram user ID
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


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
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


def init_db():
    """Инициализация базы данных - создание таблиц"""
    try:
        Base.metadata.create_all(bind=engine)
        print("[OK] База данных инициализирована! Таблицы: notes, tasks")
    except Exception as e:
        print(f"[ERROR] Ошибка инициализации базы данных: {e}")
        raise


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
        # Делаем объект detached но с загруженными данными
        db.expunge(note)
        return note
    except Exception as e:
        db.rollback()
        print(f"[ERROR] Ошибка создания заметки: {e}")
        raise
    finally:
        db.close()


def get_notes_by_user(user_id: int) -> list:
    """Получить все заметки пользователя"""
    db = SessionLocal()
    try:
        notes = db.query(Note).filter(Note.user_id == user_id).order_by(Note.created_at.desc()).all()
        # Делаем объекты detached но с загруженными данными
        for note in notes:
            db.expunge(note)
        return notes
    except Exception as e:
        print(f"[ERROR] Ошибка получения заметок: {e}")
        return []
    finally:
        db.close()


def get_note_by_id(note_id: int, user_id: int) -> Note:
    """Получить заметку по ID"""
    db = SessionLocal()
    try:
        note = db.query(Note).filter(Note.id == note_id, Note.user_id == user_id).first()
        if note:
            db.expunge(note)
        return note
    except Exception as e:
        print(f"[ERROR] Ошибка получения заметки: {e}")
        return None
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
            db.expunge(note)
        return note
    except Exception as e:
        db.rollback()
        print(f"[ERROR] Ошибка обновления заметки: {e}")
        return None
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
    except Exception as e:
        db.rollback()
        print(f"[ERROR] Ошибка удаления заметки: {e}")
        return False
    finally:
        db.close()


# Функции для работы с задачами
def create_task(user_id: int, title: str, description: str = "", interval_minutes: int = 60) -> Task:
    """Создать новую задачу"""
    db = SessionLocal()
    try:
        from datetime import timedelta
        next_notification = datetime.utcnow() + timedelta(minutes=interval_minutes)
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
        db.expunge(task)
        return task
    except Exception as e:
        db.rollback()
        print(f"[ERROR] Ошибка создания задачи: {e}")
        raise
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
            db.expunge(task)
        return tasks
    except Exception as e:
        print(f"[ERROR] Ошибка получения задач: {e}")
        return []
    finally:
        db.close()


def get_task_by_id(task_id: int, user_id: int) -> Task:
    """Получить задачу по ID"""
    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.id == task_id, Task.user_id == user_id).first()
        if task:
            db.expunge(task)
        return task
    except Exception as e:
        print(f"[ERROR] Ошибка получения задачи: {e}")
        return None
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
                from datetime import timedelta
                task.next_notification = datetime.utcnow() + timedelta(minutes=interval_minutes)
            if is_active is not None:
                task.is_active = is_active
            task.updated_at = datetime.utcnow()
            db.commit()
            db.refresh(task)
            db.expunge(task)
        return task
    except Exception as e:
        db.rollback()
        print(f"[ERROR] Ошибка обновления задачи: {e}")
        return None
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
    except Exception as e:
        db.rollback()
        print(f"[ERROR] Ошибка удаления задачи: {e}")
        return False
    finally:
        db.close()


def get_tasks_due_for_notification() -> list:
    """Получить задачи, для которых пора отправить уведомление"""
    db = SessionLocal()
    try:
        tasks = db.query(Task).filter(
            Task.is_active == True,
            Task.next_notification <= datetime.utcnow()
        ).all()
        for task in tasks:
            db.expunge(task)
        return tasks
    except Exception as e:
        print(f"[ERROR] Ошибка получения задач для уведомлений: {e}")
        return []
    finally:
        db.close()


def update_task_next_notification(task_id: int) -> Task:
    """Обновить время следующего уведомления для задачи"""
    db = SessionLocal()
    try:
        task = db.query(Task).filter(Task.id == task_id).first()
        if task:
            from datetime import timedelta
            task.next_notification = datetime.utcnow() + timedelta(minutes=task.interval_minutes)
            db.commit()
            db.refresh(task)
            db.expunge(task)
        return task
    except Exception as e:
        db.rollback()
        print(f"[ERROR] Ошибка обновления уведомления: {e}")
        return None
    finally:
        db.close()

# Gunicorn configuration file
# https://docs.gunicorn.org/en/stable/settings.html

import os

# Bind to PORT from environment or default
bind = f"0.0.0.0:{os.getenv('PORT', '5000')}"

# Worker configuration
workers = int(os.getenv("WEB_CONCURRENCY", "2"))
worker_class = "sync"
timeout = 120
keepalive = 5

# НЕ используем preload_app, чтобы healthcheck работал сразу после запуска воркера
# Каждый воркер будет инициализировать приложение независимо
preload_app = False

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Graceful timeout - время на завершение запросов при перезапуске
graceful_timeout = 30


def on_starting(server):
    """Called just before the master process is initialized."""
    print("[Gunicorn] Starting master process...")


def post_worker_init(worker):
    """
    Called just after a worker has initialized the application.
    """
    print(f"[Gunicorn] Worker {worker.pid} initialized, starting app initialization...")
    
    try:
        from app import initialize_app
        initialize_app()
        print(f"[Gunicorn] Worker {worker.pid} app initialization complete!")
    except Exception as e:
        print(f"[Gunicorn] Error initializing worker {worker.pid}: {e}")
        import traceback
        traceback.print_exc()


def worker_exit(server, worker):
    """Called just after a worker has been exited."""
    print(f"[Gunicorn] Worker {worker.pid} exiting...")

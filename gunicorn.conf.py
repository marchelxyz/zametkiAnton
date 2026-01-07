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

# Preload application for faster worker startup
preload_app = True

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"


def post_fork(server, worker):
    """
    Called just after a worker has been forked.
    This is the right place to initialize things that shouldn't be
    shared between workers (like database connections, schedulers, etc.)
    """
    print(f"[Gunicorn] Worker {worker.pid} forked, initializing...")
    
    try:
        from app import initialize_app
        initialize_app()
    except Exception as e:
        print(f"[Gunicorn] Error initializing worker {worker.pid}: {e}")


def worker_exit(server, worker):
    """Called just after a worker has been exited."""
    print(f"[Gunicorn] Worker {worker.pid} exiting...")

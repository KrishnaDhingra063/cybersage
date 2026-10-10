from celery import Celery
from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "pentest_platform",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.TOOL_TIMEOUT_SECONDS + 60,
    task_soft_time_limit=settings.TOOL_TIMEOUT_SECONDS,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
)

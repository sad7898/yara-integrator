from celery import Celery
import os

celeryApp = Celery("tasks",task_cls="tasks:ScanTask")
celeryApp.conf.broker_url='redis://127.0.0.1:6379/0'
celeryApp.conf.result_backend='redis://127.0.0.1:6379/0'


if __name__ == '__main__':
    celeryApp.start()
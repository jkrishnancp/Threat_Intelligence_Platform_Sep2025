FROM python:3.11-slim

WORKDIR /app

COPY workers/etl/requirements.txt .
RUN pip install -r requirements.txt

COPY workers/etl/ .
COPY packages/ /packages/

CMD ["celery", "-A", "tasks", "worker", "--loglevel=info"]
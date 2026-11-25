FROM mcr.microsoft.com/playwright/python:v1.49.1-jammy

WORKDIR /app

COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && chmod -R a+rX /ms-playwright

COPY openapi.yaml /app/openapi.yaml
COPY backend/app /app/app

ENV DATA_DIR=/data \
    RUN_WORKER=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

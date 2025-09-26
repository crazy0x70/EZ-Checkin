FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Asia/Shanghai

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Lark and Feishu webhook can be passed by args or env
# Default command: run service, immediate test sign-in occurs at startup
CMD ["python", "main.py"]


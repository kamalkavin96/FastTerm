FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y nginx && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 7860

# CMD ["python", "main.py"]
CMD sh -c "nginx && python main.py"
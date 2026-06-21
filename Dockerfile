FROM python:3.13-slim

ARG CACHE_BUSTER=8

ENV PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y nginx git curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Clone repository
RUN git clone -b dev-re-struct https://github.com/kamalkavin96/FastTerm.git .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy nginx config from repo
RUN cp nginx/nginx.conf /etc/nginx/nginx.conf
RUN cp nginx/index.html /usr/share/nginx/html/index.html

RUN curl -fsSL https://raw.githubusercontent.com/kamalkavin96/huggingface-container-command/refs/heads/main/uptimekuma/start.sh \
    -o /app/start.sh && chmod +x /app/start.sh

EXPOSE 7860

CMD ["/app/cmd/start.sh"]

# CMD sh -c "nginx && python src/main.py && /start.sh"
# CMD ["/start.sh"]
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y nginx git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Clone repository
RUN git clone -b dev-re-struct https://github.com/kamalkavin96/FastTerm.git .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy nginx config from repo
RUN cp nginx.conf /etc/nginx/nginx.conf

EXPOSE 7860

CMD sh -c "nginx && cd /app/src && python main.py"
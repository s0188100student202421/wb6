FROM python:3.10

WORKDIR /app

COPY . /app

RUN pip install -r requirements.txt

### 172.17.0.2
ENV DB_HOST=192.168.56.10
ENV DB_REPLICA_HOST=192.168.56.11
ENV DB_NAME=postgres
ENV DB_USER=postgres
ENV DB_PASSWORD=postgres
ENV DB_PORT=5432

CMD ["python3", "server.py"]

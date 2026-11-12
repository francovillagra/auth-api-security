FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# La misma imagen sirve para dos cosas, según el comando que reciba (ver docker-compose.yml):
#   init.py              prepara credenciales y datos de práctica (arranca como root, una sola vez por encendido)
#   console/server.py    la consola guiada
# Las dos usan solo la biblioteca estándar de Python: no hay nada que instalar.
COPY common.py init.py ./
COPY console ./console

# Todo corre sin privilegios. El servicio `init` usa esta imagen pero arranca como root, porque tiene que escribir en los volúmenes.
RUN useradd --system --uid 10002 --no-create-home --shell /usr/sbin/nologin demo
USER demo

EXPOSE 8080

CMD ["python", "console/server.py"]

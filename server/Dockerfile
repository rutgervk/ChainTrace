# ChainTrace teamserver — bouwen vanuit de hoofdmap van de repository:
#   docker build -f server/Dockerfile -t chaintrace-server .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CT_PORT=8080 CT_DATA=/data CT_WEB=/app/web

RUN useradd --system --uid 10001 --home /app chaintrace \
 && mkdir -p /data /app && chown chaintrace /data

WORKDIR /app
COPY server/chaintrace_server.py /app/chaintrace_server.py
COPY web /app/web
RUN rm -f /app/web/selftest.js /app/web/qrtest.png

USER chaintrace
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:%s/api/info'%os.environ.get('CT_PORT','8080'),timeout=4)" || exit 1

CMD ["python", "/app/chaintrace_server.py"]

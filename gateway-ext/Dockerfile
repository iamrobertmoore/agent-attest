FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py ./
# Cloud Run terminates TLS and requires a plaintext h2c listener. Behind an internal ALB
# on the FQDN path Agent Gateway documents, this needs a real certificate instead.
ENV PORT=8443
EXPOSE 8443
USER nobody
CMD ["python", "server.py"]

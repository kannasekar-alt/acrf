FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.0 requests==2.31.0 pyyaml==6.0.1
COPY inventory.yaml /app/
COPY inventory.py /app/
COPY email-server.py /app/
COPY shadow-server.py /app/
COPY agent.py /app/
CMD ["python", "-u", "agent.py"]

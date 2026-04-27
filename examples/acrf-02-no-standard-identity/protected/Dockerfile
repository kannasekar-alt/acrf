FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.0 requests==2.31.0
COPY agent_registry.py /app/
COPY api_gateway.py /app/
COPY attacker.py /app/
CMD ["python", "-u", "api_gateway.py"]

FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask==3.0.0 requests==2.31.0 cryptography==42.0.5

COPY keygen.py /app/
COPY orchestrator.py /app/
COPY booking.py /app/
COPY attacker.py /app/

CMD ["python", "-u", "booking.py"]

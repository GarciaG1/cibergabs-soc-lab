FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir requests>=2.31
COPY attack.py .
CMD ["python", "-u", "attack.py"]

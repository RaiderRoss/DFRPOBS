FROM python:3.12-alpine
RUN pip install --no-cache-dir kafka-python-ng "fastavro>=1.9.7"
COPY listener.py .
CMD ["python", "listener.py"]
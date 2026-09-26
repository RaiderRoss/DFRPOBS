FROM python:3.12-alpine
RUN pip install --no-cache-dir kafka-python-ng "fastavro>=1.9.7" "requests>=2.32"

# Avro schemas 
COPY schemas/ /schemas/

COPY listener.py collect_window.py ./
CMD ["python", "listener.py"]

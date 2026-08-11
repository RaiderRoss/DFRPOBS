FROM python:3.12-alpine
RUN pip install --no-cache-dir kafka-python-ng "fastavro>=1.9.7"

# Avro schemas are vendored into the image rather than bind-mounted from a
# local Fineract checkout, so this listener needs nothing outside the repo.
# They are copied from fineract-avro-schemas/src/main/ of the Fineract source
# at the tag pinned in docker-compose-fineract.yml -- keep the two in step.
COPY schemas/ /schemas/

COPY listener.py .
CMD ["python", "listener.py"]

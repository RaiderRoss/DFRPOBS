## Build
- ```./gradlew --no-daemon --console=plain :fineract-provider:jibDockerBuild -x test```

## Run
- Start with ```docker compose -f docker-compose-postgresql-kafka.yml up -d```

## Seed
- ```chmod +x seed-fineract.sh```
- ```./seed-fineract.sh```

## View DB
- ```docker exec -it <postgres-container-name> psql -U postgres -d fineract_default```

# SQL Stuff
Currently the tables the seed script affects are m_office, m_staff, m_client, m_product_loan and m_savings_product
- Can use ```\dt``` to view tables in psql

# External events
External events are the state changing actions which we can capture and make available to kafka. They get added to the ```m_external_event``` with status **TO_BE_SENT**.
the "Send Asynchronous Events" scheduled job picks them up and publishes to Kafka, but can be triggered manually with:
```
curl -sk -X POST "https://localhost:8443/fineract-provider/api/v1/jobs/$(
  curl -sk https://localhost:8443/fineract-provider/api/v1/jobs \
    -H "Authorization: Basic $(echo -n mifos:password | base64)" \
    -H "Fineract-Platform-TenantId: default" | jq -r '.[] | select(.displayName=="Send Asynchronous Events") | .jobId'
)?command=executeJob" \
  -H "Authorization: Basic $(echo -n mifos:password | base64)" \
  -H "Fineract-Platform-TenantId: default"
```

## Viewing events
Two ways to check:
- Database — the staging table before they hit Kafka:
```
docker exec -it fineract-db-1 psql -U postgres -d fineract_default \
-c "SELECT id, type, category, status, created_at, sent_at FROM m_external_event ORDER BY id DESC LIMIT 10;" 
```
- Kafka consumer — see what actually landed on the topic:
```
docker exec -it fineract-kafka-1 /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic external-events \
  --from-beginning \
  --max-messages 10
```
## Configuring Events
- Endpoint to see which events are available to turn on
```
curl -sk https://localhost:8443/fineract-provider/api/v1/externalevents/configuration \
  -H "Authorization: Basic $(echo -n mifos:password | base64)" \
  -H "Fineract-Platform-TenantId: default" | jq .
```
- Script to turn on collection for specific types
```
curl -sk -X PUT https://localhost:8443/fineract-provider/api/v1/externalevents/configuration \
  -H "Authorization: Basic $(echo -n mifos:password | base64)" \
  -H "Fineract-Platform-TenantId: default" \
  -H "Content-Type: application/json" \
  -d '{
    "externalEventConfigurations": {
      "ClientActivateBusinessEvent": true,
      "ClientCreateBusinessEvent": true,
      "LoanCreatedBusinessEvent": true,
      "LoanApprovedBusinessEvent": true,
      "LoanDisbursalBusinessEvent": true,
      "LoanRepaymentTransactionBusinessEvent": true,
      "SavingsActivateBusinessEvent": true,
      "SavingsDepositBusinessEvent": true
    }
  }'
```

# Kafka
The docker compose creates 1 manager and 2 workers. For our scale 1 worker is probably enough so you can change the following in the **docker-compose-postgresql-kafka.yml** to save some resources:
```
fineract-worker:
  deploy:
    mode: replicated
    replicas: 1
  ports:
    - "8444:8443"
```
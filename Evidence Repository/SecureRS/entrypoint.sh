#!/bin/bash
set -e

# Development escape hatches, read by SecureRS/settings.py. Anything other than
# 0/false/no/off leaves the control enforced.
is_disabled() {
    case "$(echo "${1}" | tr '[:upper:]' '[:lower:]')" in
        0|false|no|off) return 0 ;;
        *) return 1 ;;
    esac
}

if is_disabled "${ENFORCE_2FA:-True}"; then
    echo "WARNING: ENFORCE_2FA is off — OTP challenges are disabled (development only)."
fi

if is_disabled "${ENFORCE_SSL:-True}"; then
    SSL_ENABLED=0
    echo "WARNING: ENFORCE_SSL is off — serving plain HTTP (development only)."
else
    SSL_ENABLED=1
fi

echo "Running migrations..."
python manage.py makemigrations pde
python manage.py migrate

# Only create a superuser if one doesn't already exist, and only if
# credentials were actually supplied via environment variables.
if [ -n "$DJANGO_SUPERUSER_USERNAME" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ] && [ -n "$DJANGO_SUPERUSER_EMAIL" ]; then
    echo "Ensuring superuser '$DJANGO_SUPERUSER_USERNAME' exists..."
    python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='$DJANGO_SUPERUSER_USERNAME').exists():
    User.objects.create_superuser('$DJANGO_SUPERUSER_USERNAME', '$DJANGO_SUPERUSER_EMAIL', '$DJANGO_SUPERUSER_PASSWORD')
    print('Superuser created.')
else:
    print('Superuser already exists, skipping.')
"
else
    echo "DJANGO_SUPERUSER_USERNAME/EMAIL/PASSWORD not set — skipping superuser creation."
    echo "Create one manually with: docker exec -it <container> python manage.py createsuperuser"
fi

if [ "$SSL_ENABLED" -eq 0 ]; then
    echo "Starting server on http://0.0.0.0:${HTTP_PORT:-8000} ..."
    exec python manage.py runserver "0.0.0.0:${HTTP_PORT:-8000}"
fi

CERT_DIR="/SecureRS/certs"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "No certificate found, generating a self-signed one (valid 5 years)..."
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -days 1825 \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
else
    echo "Using existing certificate in $CERT_DIR"
fi

echo "Starting server..."
exec python manage.py runsslserver 0.0.0.0:443 --certificate "$CERT_FILE" --key "$KEY_FILE"
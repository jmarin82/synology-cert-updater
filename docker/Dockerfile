# Imagen base de Python
FROM python:3.11-slim

# Variables de entorno
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Instalación de dependencias del sistema
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
        curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Instalación de dependencias de Python
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar el código de la aplicación
COPY app/ /app
COPY entrypoint.sh /entrypoint.sh

WORKDIR /app

# Permisos de ejecución para el entrypoint
RUN chmod +x /entrypoint.sh

# Definir el entrypoint
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-u", "synology-cert-updater.py"]
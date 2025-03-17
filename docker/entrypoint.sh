#!/bin/bash
set -e  # Terminar el script si ocurre un error

# Manejo de señales
trap 'echo "Señal SIGTERM recibida. Finalizando..."; exit 143' SIGTERM
trap 'echo "Señal SIGINT recibida. Cancelando..."; exit 130' SIGINT
trap 'echo "Error inesperado en el script. Código de salida: $?"; exit 1' ERR

# Ejecutar el comando principal del contenedor
echo "Iniciando el proceso: $@"
exec "$@"

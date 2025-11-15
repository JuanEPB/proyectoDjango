import requests
import os

API_BASE_URL = os.getenv("API_URL")  # Cambia si tu API está en otra URL


def obtener_medicamentos():
    try:
        response = requests.get(f"{API_BASE_URL}/api/medicamentos/all")
        if response.status_code == 200:
            return response.json()
    except requests.RequestException as e:
        print("Error al conectar con la API:", e)
    return []

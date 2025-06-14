import requests

API_BASE_URL = "http://localhost:3000"  # Cambia si tu API está en otra URL

def obtener_medicamentos():
    try:
        response = requests.get(f"{API_BASE_URL}/api/medicamentos/all")
        if response.status_code == 200:
            return response.json()
    except requests.RequestException as e:
        print("Error al conectar con la API:", e)
    return []

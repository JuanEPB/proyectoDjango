import requests
from django.shortcuts import render, redirect
from datetime import datetime

def lista_medicamentos(request):
    token = request.session.get("jwt")
    if not token:
        return redirect("login")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    try:
        response = requests.get("http://localhost:3000/api/medicamentos/all", headers=headers)
        if response.status_code == 200:
            medicamentos = response.json()
        else:
            medicamentos = []
    except requests.RequestException:
        medicamentos = []

    return render(request, 'core/medicamentos.html', {'medicamentos': medicamentos})

# vista de login
def login_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        contraseña = request.POST.get("contraseña")

        try:
            response = requests.post("http://localhost:3000/api/auth/login", json={
                "email": email,
                "contraseña": contraseña
            })

            if response.status_code == 201:
                token = response.json().get("access_token")
                request.session["jwt"] = token
                return redirect("medicamentos")
            else:
                return render(request, "core/login.html", {"error": "Credenciales incorrectas."})
        
        except requests.RequestException:
            return render(request, "core/login.html", {"error": "Error al conectar con la API."})

    return render(request, "core/login.html")

def logout_view(request):
    request.session.flush()
    return redirect("login")

# vista de inventario
def inventory_view(request):
    token = request.session.get("jwt")
    if not token:
        return redirect("login")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    try:
        response = requests.get("http://localhost:3000/api/medicamentos/all", headers=headers)
        if response.status_code == 200:
            inventory = response.json()
        else:
            inventory = []
    except requests.RequestException:
        inventory = []

    return render(request, 'core/inventory.html', {'inventory': inventory})

# vista de reportes
def report_view(request):
    token = request.session.get("jwt")
    if not token:
        return redirect("login")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    try:
        response = requests.get("http://localhost:3000/api/medicamentos/all", headers=headers)
        if response.status_code == 200:
            reports = response.json()
        else:
            reports = []
    except requests.RequestException:
        reports = []

    return render(request, 'core/reports.html', {'reports': reports})

# vista de users
def user_view(request):
    token = request.session.get("jwt")
    if not token:
        return redirect("login")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    try:
        response = requests.get("http://localhost:3000/api/medicamentos/all", headers=headers)
        if response.status_code == 200:
            users = response.json()
        else:
            users = []
    except requests.RequestException:
        users = []

    return render(request, 'core/users.html', {'users': users})

# vista de pedidos
def order_view(request):
    token = request.session.get("jwt")
    if not token:
        return redirect("login")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    try:
        response = requests.get("http://localhost:3000/api/medicamentos/all", headers=headers)
        if response.status_code == 200:
            orders = response.json()
        else:
            orders = []
    except requests.RequestException:
        orders = []

    return render(request, 'core/orders.html', {'orders': orders})

# vista de proveedores
def supplier_view(request):
    token = request.session.get("jwt")
    if not token:
        return redirect("login")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    try:
        response = requests.get("http://localhost:3000/api/medicamentos/all", headers=headers)
        if response.status_code == 200:
            supplier = response.json()
        else:
            supplier = []
    except requests.RequestException:
        supplier = []

    return render(request, 'core/supplier.html', {'supplier': supplier})

# vista de configuracion
def settings_view(request):
    token = request.session.get("jwt")
    if not token:
        return redirect("login")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    try:
        response = requests.get("http://localhost:3000/api/medicamentos/all", headers=headers)
        if response.status_code == 200:
            settings = response.json()
        else:
            settings = []
    except requests.RequestException:
        settings = []

    return render(request, 'core/settings.html', {'settings': settings})


# vista de crear medicamento
def create_medicamento_view(request):
    token = request.session.get("jwt")
    if not token:
        return redirect("login")

    headers = {
        "Authorization": f"Bearer {token}"
    }   
    if request.method == "POST":
        nombre = request.POST.get("nombre")
        descripcion = request.POST.get("descripcion")
        precio = request.POST.get("precio")
        cantidad = request.POST.get("cantidad")

        try:
            
            response = requests.post("http://localhost:3000/api/medicamentos/create", json={
                "nombre": nombre,
                "descripcion": descripcion,
                "precio": precio,
                "cantidad": cantidad
            }, headers=headers)

            if response.status_code == 201:
                return redirect("medicamentos")
            else:
                return render(request, "core/create_medicamento.html", {"error": "Error al crear el medicamento."})
        
        except requests.RequestException:
            return render(request, "core/create_medicamento.html", {"error": "Error al conectar con la API."})
        

def navbar(request):
    return render(request, 'core/asda.html')

def lista_medicamentos(request):
    token = request.session.get("jwt")
    if not token:
        return redirect("login")

    headers = {"Authorization": f"Bearer {token}"}
    medicamentos = []

    try:
        response = requests.get("http://localhost:3000/api/medicamentos/all", headers=headers)
        if response.status_code == 200:
            medicamentos = response.json()
    except requests.RequestException:
        pass

    # Resumen de TODOS los medicamentos
    total_medicamentos = len(medicamentos)
    stock_critico = sum(1 for m in medicamentos if m.get("stock", 0) < 10)

    caducados = 0
    fecha_hoy = datetime.now().date()
    for med in medicamentos:
        try:
            fecha_caducidad = datetime.strptime(med.get("caducidad", ""), "%Y-%m-%d").date()
            if fecha_caducidad < fecha_hoy:
                caducados += 1
        except ValueError:
            continue

    # Ordenar por createdAt si existe, sino por id o sin orden
    try:
        medicamentos_ordenados = sorted(medicamentos, key=lambda x: x.get('createdAt', ''), reverse=True)
    except KeyError:
        medicamentos_ordenados = medicamentos

    ultimos_10 = medicamentos_ordenados[:10]

    # Datos para gráfica → SOLO los últimos 10 medicamentos
    nombres = [m.get("nombre", "") for m in ultimos_10]
    cantidades = [m.get("stock", 0) for m in ultimos_10]

    contexto = {
        "medicamentos": ultimos_10,
        "total_medicamentos": total_medicamentos,
        "stock_critico": stock_critico,
        "caducados": caducados,
        "nombres": nombres,
        "cantidades": cantidades,
    }
    return render(request, 'core/medicamentos.html', contexto)
import requests

from django.shortcuts import render, redirect

# Helper para verificar sesión y realizar requests
def get_authenticated_data(request, url):
    token = request.session.get("jwt")
    if not token:
        return redirect("login"), []

    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return None, response.json()
        return None, []
    except requests.RequestException:
        return None, []

def lista_medicamentos(request):
    redirect_response, medicamentos = get_authenticated_data(request, "http://localhost:3000/api/medicamentos/all")
    if redirect_response:
        return redirect_response
    return render(request, 'core/medicamentos.html', {'medicamentos': medicamentos})

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

def inventory_view(request):
    redirect_response, inventory = get_authenticated_data(request, "http://localhost:3000/api/medicamentos/all")
    if redirect_response:
        return redirect_response
    return render(request, 'core/inventory.html', {'inventory': inventory})

def report_view(request):
    redirect_response, reports = get_authenticated_data(request, "http://localhost:3000/api/medicamentos/all")
    if redirect_response:
        return redirect_response
    return render(request, 'core/reports.html', {'reports': reports})

def user_view(request):
    redirect_response, users = get_authenticated_data(request, "http://localhost:3000/api/medicamentos/all")
    if redirect_response:
        return redirect_response
    return render(request, 'core/users.html', {'users': users})

def order_view(request):
    redirect_response, orders = get_authenticated_data(request, "http://localhost:3000/api/medicamentos/all")
    if redirect_response:
        return redirect_response
    return render(request, 'core/orders.html', {'orders': orders})

def settings_view(request):
    redirect_response, settings = get_authenticated_data(request, "http://localhost:3000/api/medicamentos/all")
    if redirect_response:
        return redirect_response
    return render(request, 'core/settings.html', {'settings': settings})

def create_medicamento_view(request):
    token = request.session.get("jwt")
    if not token:
        return redirect("login")

    headers = {"Authorization": f"Bearer {token}"}

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

    return render(request, "core/create_medicamento.html")
#////////////////////////////////////////////////////////////////////////////
def supplier_view(request):
    redirect_response, proveedores = get_authenticated_data(request, "http://localhost:3000/api/proveedores/all")
    if redirect_response:
        return redirect_response
    return render(request, 'core/supplier.html', {'proveedores': proveedores})
def add_supplier_view(request):
    token = request.session.get("jwt")
    if not token:
        return redirect("login")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    error = None

    if request.method == "POST":
        data = {
            "nombre": request.POST.get("nombre"),
            "contacto": request.POST.get("contacto"),
            "direccion": request.POST.get("direccion"),
        }

       # try:
           # response = requests.post("http://localhost:3000/api/proveedores/create", json=data, headers=headers)
          #  if response.status_code == 201:
          #      return redirect("suppliers")
          #  else:
          #      error = "No se pudo agregar el proveedor. Verifica los datos."
        #except requests.RequestException:
        #    error = "Error de conexión con la API."

    # Cargar lista de proveedores siempre
    try:
        response = requests.get("http://localhost:3000/api/proveedores/all", headers=headers)
        proveedores = response.json() if response.status_code == 200 else []
    except requests.RequestException:
        proveedores = []

    return render(request, "core/supplier.html", {
        "proveedores": proveedores,
        "error": error
    })




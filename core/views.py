# views.py
import json
from datetime import datetime, date
from collections import Counter
import requests
from django.http import JsonResponse, HttpResponseBadRequest
from django.shortcuts import render, redirect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

# =========================
# Config
# =========================
NEST_BASE = "http://127.0.0.1:3000"  # API NestJS
API = {
    "meds_all": f"{NEST_BASE}/api/medicamentos/all",
    "meds_count": f"{NEST_BASE}/api/medicamentos/count",
    "meds_get": f"{NEST_BASE}/api/medicamentos",  # /:id
    "meds_create": f"{NEST_BASE}/api/medicamentos/create",
    "meds_update": f"{NEST_BASE}/api/medicamentos/update",  # /:id
    "meds_delete": f"{NEST_BASE}/api/medicamentos/delete",  # /:id
    "users_all": f"{NEST_BASE}/api/users/all",
    "users_get": f"{NEST_BASE}/api/users",  # /:id
    "users_create": f"{NEST_BASE}/api/users/create",
    "users_update": f"{NEST_BASE}/api/users/update",  # /:id
    "users_delete": f"{NEST_BASE}/api/users/delete",  # /:id
    "prov_all": f"{NEST_BASE}/api/proveedores/all",
    "prov_create": f"{NEST_BASE}/api/proveedores/create",
    "prov_update": f"{NEST_BASE}/api/proveedores/update",  # /:id
    "prov_delete": f"{NEST_BASE}/api/proveedores/delete",  # /:id
    "venta": f"{NEST_BASE}/api/venta",
    "cats_all": f"{NEST_BASE}/api/categorias/all",
}

# =========================
# Helpers
# =========================
def _auth_headers(request):
    token = request.session.get("jwt")
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers

def _get(request, url):
    try:
        r = requests.get(url, headers=_auth_headers(request), timeout=10)
        if r.status_code == 401:
            return "unauthorized", []
        if r.ok:
            ctype = r.headers.get("content-type", "")
            return None, (r.json() if ctype.startswith("application/json") else [])
    except requests.RequestException:
        pass
    return None, []

def _post(request, url, payload):
    try:
        r = requests.post(url, json=payload, headers=_auth_headers(request), timeout=10)
        if r.status_code == 401:
            return "unauthorized", None
        return None, r
    except requests.RequestException:
        return None, None

def _put(request, url, payload):
    try:
        r = requests.put(url, json=payload, headers=_auth_headers(request), timeout=10)
        if r.status_code == 401:
            return "unauthorized", None
        return None, r
    except requests.RequestException:
        return None, None

def _delete(request, url):
    try:
        r = requests.delete(url, headers=_auth_headers(request), timeout=10)
        if r.status_code == 401:
            return "unauthorized", None
        return None, r
    except requests.RequestException:
        return None, None

def _parse_date(s):
    if not s:
        return None
    try:
        # ISO YYYY-MM-DD
        return datetime.fromisoformat(s).date()
    except Exception:
        try:
            dd, mm, yyyy = s.split("/")
            return date(int(yyyy), int(mm), int(dd))
        except Exception:
            return None

# =========================
# Bridge (JS -> Django session)
# =========================
@require_POST
@csrf_exempt
def bridge_store_token(request):
    """
    El JS guarda el accessToken en localStorage y nos lo manda aquí
    para que Django lo tenga en sesión y pueda consumir la API.
    """
    try:
        data = json.loads(request.body or "{}")
        token = data.get("accessToken")
        if not token:
            return HttpResponseBadRequest("no token")
        request.session["jwt"] = token
        request.session.modified = True
        return JsonResponse({"ok": True})
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=400)

@require_POST
@csrf_exempt
def bridge_clear_token(request):
    request.session.pop("jwt", None)
    return JsonResponse({"ok": True})

# =========================
# Login / Logout (UI)
# =========================
def login_view(request):
    # El login real lo hace el JS (auth.js) contra Nest.
    return render(request, "core/login.html")

def logout_view(request):
    request.session.flush()
    return redirect("login")

# =========================
# Dashboard / Medicamentos
# =========================


def medicamentos_view(request):
    err, meds = _get(request, API["meds_all"])
    if err == "unauthorized":
        return redirect("login")
    meds = meds if isinstance(meds, list) else []

    # KPIs
    total = len(meds)
    criticos = sum(1 for m in meds if (m.get("stock") or 0) < 10)
    hoy = date.today()
    caducados = 0
    for m in meds:
        d = _parse_date(m.get("caducidad"))
        if d and d < hoy:
            caducados += 1

    resumen = {"disponibles": max(0, total - criticos - caducados),
               "criticos": criticos, "caducados": caducados}

    # Top stock
    top = sorted(meds, key=lambda m: m.get("stock") or 0, reverse=True)[:15]
    stockTop = {"labels": [m.get("nombre") or "" for m in top],
                "values": [m.get("stock") or 0 for m in top]}

    # Categorías
    def cat_name(m):
        c = m.get("categoria")
        return c.get("nombre") if isinstance(c, dict) else (c or "Sin categoría")
    cnt = Counter(cat_name(m) for m in meds)
    categorias = {"labels": list(cnt.keys()), "values": list(cnt.values())}

    # Rotación dummy
    rotacion = {"labels": categorias["labels"], "values": [v*6 for v in categorias["values"]]}

    # Vencimientos
    def within_days(s, days):
        d = _parse_date(s); 
        return bool(d and hoy <= d <= date.fromordinal(hoy.toordinal()+days))
    vencimientos = {
        "d30": sum(1 for m in meds if within_days(m.get("caducidad"), 30)),
        "d60": sum(1 for m in meds if within_days(m.get("caducidad"), 60)),
        "d90": sum(1 for m in meds if within_days(m.get("caducidad"), 90)),
    }
    meds_json = json.dumps(meds, ensure_ascii=False)  # listado completo para JS

    chart_data_json = json.dumps({
        "resumen": resumen,
        "stockTop": stockTop,
        "categorias": categorias,
        "rotacion": rotacion,
        "vencimientos": vencimientos,
    }, ensure_ascii=False)

    contexto = {
        "meds_json": meds_json,
        "chart_data_json": chart_data_json,
     # <— NUEVO
    }
    return render(request, "core/medicamentos.html", contexto)
# =========================
# Inventory (lista + paginación)
# =========================
def inventory_view(request):
    # total
    _, count_data = _get(request, API["meds_count"])
    total_medicamentos = 0
    if isinstance(count_data, dict):
        for v in count_data.values():
            if isinstance(v, int):
                total_medicamentos = v
                break

    # lista
    err, meds = _get(request, API["meds_all"])
    if err == "unauthorized":
        return redirect("login")
    meds = meds if isinstance(meds, list) else meds.get("data", [])

    paginator = Paginator(meds, 10)
    page_number = request.GET.get("page", 1)
    try:
        page_obj = paginator.page(page_number)
    except PageNotAnInteger:
        page_obj = paginator.page(1)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)

    context = {
        "inventory": page_obj.object_list,
        "page_obj": page_obj,
        "total_medicamentos": total_medicamentos,
    }
    return render(request, "core/inventory.html", context)

# Crear medicamento
def create_medicamento_view(request):
    # proveedores para el form (si los necesitas)
    _, proveedores = _get(request, API["prov_all"])

    error = None
    if request.method == "POST":
        payload = {
            "nombre": request.POST.get("nombre"),
            "lote": request.POST.get("lote"),
            "caducidad": request.POST.get("caducidad"),
            "stock": int(request.POST.get("stock") or 0),
            "precio": float(request.POST.get("precio") or 0),
            "proveedor": {"id": int(request.POST.get("proveedor_id"))} if request.POST.get("proveedor_id") else None,
            "categoria": {"id": int(request.POST.get("categoria_id"))} if request.POST.get("categoria_id") else None,
        }
        err, r = _post(request, API["meds_create"], payload)
        if err == "unauthorized":
            return redirect("login")
        if r and r.status_code in (200, 201):
            return redirect("inventory")
        error = f"Error al crear medicamento: {r.status_code if r else 'sin respuesta'}"

    return render(
        request,
        "core/inventory.html",
        {"proveedores": proveedores if isinstance(proveedores, list) else [], "error": error},
    )

# Editar medicamento
def edit_medicamento_view(request, medicamento_id):
    if request.method == "POST":
        payload = {
            "nombre": request.POST.get("nombre"),
            "lote": request.POST.get("lote"),
            "caducidad": request.POST.get("caducidad"),
            "stock": int(request.POST.get("stock") or 0),
            "precio": float(request.POST.get("precio") or 0),
            "proveedor": {"id": int(request.POST.get("proveedor_id"))} if request.POST.get("proveedor_id") else None,
            "categoria": {"id": int(request.POST.get("categoria_id"))} if request.POST.get("categoria_id") else None,
        }
        err, r = _put(request, f"{API['meds_update']}/{medicamento_id}", payload)
        if err == "unauthorized":
            return redirect("login")
        if r and r.status_code == 200:
            return redirect("inventory")
        return render(
            request,
            "core/edit_medicamento.html",
            {"medicamento": payload, "error": f"Error al actualizar: {r.status_code if r else 'sin respuesta'}"},
        )
    else:
        err, data = _get(request, f"{API['meds_get']}/{medicamento_id}")
        if err == "unauthorized":
            return redirect("login")
        return render(request, "core/edit_medicamento.html", {"medicamento": data or {}})

# Eliminar medicamento
def eliminar_medicamento_view(request, medicamento_id):
    if request.method == "POST":
        err, r = _delete(request, f"{API['meds_delete']}/{medicamento_id}")
        if err == "unauthorized":
            return redirect("login")
        if r and r.status_code in (200, 204):
            return redirect("inventory")
        return render(request, "core/inventory.html", {"error": "Error al eliminar el medicamento."})
    return redirect("inventory")

# Detalle medicamento
def detalle_medicamento_view(request, medicamento_id):
    err, data = _get(request, f"{API['meds_get']}/{medicamento_id}")
    if err == "unauthorized":
        return redirect("login")
    if data:
        return render(request, "core/detalle_medicamento.html", {"medicamento": data})
    return redirect("inventory")

# =========================
# Reportes
# =========================
def report_view(request):
    err, reports = _get(request, API["meds_all"])
    if err == "unauthorized":
        return redirect("login")
    return render(request, "core/reports.html", {"reports": reports if isinstance(reports, list) else []})

# =========================
# Pedidos
# =========================
def order_view(request):
    err, orders = _get(request, API["meds_all"])
    if err == "unauthorized":
        return redirect("login")
    return render(request, "core/orders.html", {"orders": orders if isinstance(orders, list) else []})

# =========================
# Configuración
# =========================
def settings_view(request):
    err, settings = _get(request, API["meds_all"])
    if err == "unauthorized":
        return redirect("login")
    return render(request, "core/settings.html", {"settings": settings if isinstance(settings, list) else []})

# =========================
# Proveedores
# =========================
def supplier_view(request):
    err, data = _get(request, API["prov_all"])
    if err == "unauthorized":
        return redirect("login")
    proveedores_list = data if isinstance(data, list) else []

    page = request.GET.get("page", 1)
    paginator = Paginator(proveedores_list, 10)
    try:
        proveedores = paginator.page(page)
    except PageNotAnInteger:
        proveedores = paginator.page(1)
    except EmptyPage:
        proveedores = paginator.page(paginator.num_pages)

    context = {"proveedores": proveedores, "page": proveedores.number, "total_pages": paginator.num_pages}
    return render(request, "core/supplier.html", context)

def add_supplier_view(request):
    error = None
    if request.method == "POST":
        payload = {
            "nombre": request.POST.get("nombre"),
            "contacto": request.POST.get("contacto"),
            "direccion": request.POST.get("direccion"),
        }
        err, r = _post(request, API["prov_create"], payload)
        if err == "unauthorized":
            return redirect("login")
        if r and r.status_code in (200, 201):
            return redirect("suppliers")
        error = f"No se pudo agregar el proveedor: {r.status_code if r else 'sin respuesta'}"

    # recargar lista
    err, data = _get(request, API["prov_all"])
    proveedores = data if isinstance(data, list) else []
    return render(request, "core/supplier.html", {"proveedores": proveedores, "error": error})

def edit_supplier_view(request, id):
    if request.method == "POST":
        payload = {
            "nombre": request.POST.get("nombre"),
            "contacto": request.POST.get("contacto"),
            "direccion": request.POST.get("direccion"),
        }
        err, r = _put(request, f"{API['prov_update']}/{id}", payload)
        if err == "unauthorized":
            return redirect("login")
        if r and r.status_code == 200:
            return redirect("suppliers")
    return redirect("suppliers")

def delete_supplier_view(request, id):
    err, _ = _delete(request, f"{API['prov_delete']}/{id}")
    if err == "unauthorized":
        return redirect("login")
    return redirect("suppliers")

#========================
# Usuarios
#========================
# --- USUARIOS ---

def user_view(request):
    err, users = _get(request, API["users_all"])
    if err == "unauthorized":
        return redirect("login")
    return render(request, "core/users.html", {"users": users if isinstance(users, list) else []})

def add_user_view(request):
    if request.method == "POST":
        payload = {
            "nombre": request.POST.get("nombre"),
            "apellido": request.POST.get("apellido"),
            "rol": request.POST.get("rol"),
            "email": request.POST.get("email"),
            "contraseña": request.POST.get("contraseña"),
        }
        err, r = _post(request, API["users_create"], payload)
        if err == "unauthorized":
            return redirect("login")
        if r and r.status_code in (200, 201):
            return redirect("users")
        return render(request, "core/add_user.html", {"error": f"Error: {r.status_code if r else 'sin respuesta'}"})
    return render(request, "core/add_user.html")

def edit_user_view(request, user_id):
    if request.method == "POST":
        payload = {
            "nombre": request.POST.get("nombre"),
            "apellido": request.POST.get("apellido"),
            "rol": request.POST.get("rol"),
            "email": request.POST.get("email"),
        }
        err, r = _put(request, f"{API['users_update']}/{user_id}", payload)
        if err == "unauthorized":
            return redirect("login")
        if r and r.status_code == 200:
            return redirect("users")
        return render(request, "core/edit_user.html", {"user": payload, "error": "No se pudo actualizar"})
    else:
        err, u = _get(request, f"{API['users_get']}/{user_id}")
        if err == "unauthorized":
            return redirect("login")
        return render(request, "core/edit_user.html", {"user": u or {}})

def delete_user_view(request, user_id):
    err, r = _delete(request, f"{API['users_delete']}/{user_id}")
    if err == "unauthorized":
        return redirect("login")
    return redirect("users")

# =========================
# Carrito / Ventas
# =========================
API_MEDICAMENTOS_URL = API["meds_all"]
API_VENTA_URL = API["venta"]

def obtener_medicamentos_con_token(request):
    err, data = _get(request, API_MEDICAMENTOS_URL)
    if err == "unauthorized":
        return []
    return data if isinstance(data, list) else []

def carrito_view(request):
    token = request.session.get("jwt")
    if not token:
        return redirect("login")

    filtro = request.GET.get("stock")
    medicamentos = obtener_medicamentos_con_token(request)

    if filtro == "con":
        medicamentos = [m for m in medicamentos if (m.get("stock") or 0) > 0]
    elif filtro == "sin":
        medicamentos = [m for m in medicamentos if (m.get("stock") or 0) <= 0]

    paginator = Paginator(medicamentos, 10)
    page_number = request.GET.get("page", 1)
    page_obj = paginator.get_page(page_number)

    carrito = request.session.get("carrito", [])
    total = sum(item["precio"] * item["cantidad"] for item in carrito)
    compra_exitosa = request.session.pop("compra_exitosa", False)

    return render(
        request,
        "core/carrito.html",
        {
            "medicamentos": page_obj,
            "page_obj": page_obj,
            "carrito": carrito,
            "total_carrito": total,
            "compra_exitosa": compra_exitosa,
            "filtro": filtro,
        },
    )

@csrf_exempt
def agregar_al_carrito(request, medicamento_id):
    if request.method == "POST":
        token = request.session.get("jwt")
        if not token:
            return redirect("login")

        cantidad = int(request.POST.get("cantidad", 1))

        inventory = obtener_medicamentos_con_token(request)
        medicamento = next((m for m in inventory if str(m.get("id")) == str(medicamento_id)), None)
        if not medicamento:
            return redirect("carrito")

        precio = float(medicamento.get("precio") or 0.0)
        carrito = request.session.get("carrito", [])
        for item in carrito:
            if str(item["id"]) == str(medicamento_id):
                item["cantidad"] += cantidad
                item["total"] = item["cantidad"] * precio
                break
        else:
            carrito.append(
                {
                    "id": medicamento.get("id"),
                    "nombre": medicamento.get("nombre"),
                    "precio": precio,
                    "cantidad": cantidad,
                    "total": precio * cantidad,
                }
            )
        request.session["carrito"] = carrito
    return redirect("carrito")

@csrf_exempt
def quitar_del_carrito(request, medicamento_id):
    if request.method == "POST":
        carrito = request.session.get("carrito", [])
        carrito = [item for item in carrito if str(item["id"]) != str(medicamento_id)]
        request.session["carrito"] = carrito
    return redirect("carrito")

@csrf_exempt
def realizar_compra(request):
    if request.method == "POST":
        token = request.session.get("jwt")
        if not token:
            return redirect("login")

        carrito = request.session.get("carrito", [])
        if not carrito:
            return redirect("carrito")

        total = sum(item["precio"] * item["cantidad"] for item in carrito)
        detalles = [
            {
                "medicamentoId": item["id"],
                "cantidad": item["cantidad"],
                "precioUnitario": item["precio"],
            }
            for item in carrito
        ]
        payload = {"total": total, "detalles": detalles}

        try:
            r = requests.post(API_VENTA_URL, json=payload, headers=_auth_headers(request), timeout=12)
            if r.status_code in (200, 201):
                request.session["carrito"] = []
                request.session["compra_exitosa"] = True
                return redirect("carrito")
            else:
                error_msg = f"Error al realizar la compra: {r.status_code} - {r.text}"
                return render(
                    request,
                    "core/carrito.html",
                    {"carrito": carrito, "total_carrito": total, "error": error_msg},
                )
        except requests.RequestException as e:
            return render(
                request,
                "core/carrito.html",
                {"carrito": carrito, "total_carrito": total, "error": f"Error de conexión con la API: {e}"},
            )
    return redirect("carrito")

# =========================
# Vistas varias
# =========================
def navbar(request):
    return render(request, "core/asda.html")

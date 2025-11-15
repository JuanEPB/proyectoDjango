# views.py
import json
from datetime import datetime, date, timedelta
from collections import Counter
import requests
import unicodedata
import urllib.parse

from django.http import JsonResponse, HttpResponse, HttpResponseBadRequest
from django.shortcuts import render, redirect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q

from django.conf import settings
from api_client import API_BASE_URL  # Asegúrate de que este archivo exista y tenga la URL base correcta
# Ajusta estos imports a tus modelos reales

# =========================
# Config
# =========================
NEST_BASE = "http://18.191.169.4:3000"

API = {
    "meds_all":     f"{NEST_BASE}/api/medicamentos/all",
    "meds_count":   f"{NEST_BASE}/api/medicamentos/count",
    "meds_get":     f"{NEST_BASE}/api/medicamentos",  # /:id
    "meds_create":  f"{NEST_BASE}/api/medicamentos/create",
    "meds_update":  f"{NEST_BASE}/api/medicamentos/update",  # /:id
    "meds_delete":  f"{NEST_BASE}/api/medicamentos/delete",  # /:id
    "users_all":    f"{NEST_BASE}/api/users/all",
    "users_get":    f"{NEST_BASE}/api/users",  # /:id
    "users_create": f"{NEST_BASE}/api/users/create",
    "users_update": f"{NEST_BASE}/api/users/update",  # /:id
    "users_delete": f"{NEST_BASE}/api/users/delete",  # /:id
    "prov_all":     f"{NEST_BASE}/api/proveedores/all",
    "prov_create":  f"{NEST_BASE}/api/proveedores/create",
    "prov_update":  f"{NEST_BASE}/api/proveedores/update",  # /:id
    "prov_delete":  f"{NEST_BASE}/api/proveedores/delete",  # /:id
    "venta":        f"{NEST_BASE}/api/venta",
    "cats_all":     f"{NEST_BASE}/api/categorias/all",

    # Pedidos
    "orders_list":   f"{NEST_BASE}/api/pedidos",
    "orders_detail": f"{NEST_BASE}/api/pedidos",  # /:id
    "orders_create": f"{NEST_BASE}/api/pedidos",
    "orders_patch":  f"{NEST_BASE}/api/pedidos",  # /:id

    # Búsquedas (fallbacks incluidos)
    "meds_search":    f"{NEST_BASE}/api/medicamentos/all",
    "prov_search":    f"{NEST_BASE}/api/proveedores/all",
    "orders_search":  f"{NEST_BASE}/api/pedidos",
    "ventas_search":  f"{NEST_BASE}/api/ventas/search",
    "ventas_all":     f"{NEST_BASE}/api/ventas",
}

# Documentos / Ventas (como constantes claras)
DOCS_LIST        = f"{NEST_BASE}/api/documentos"              # ...?tipo=venta|IA (si lo usas)
DOCS_FILE        = f"{NEST_BASE}/api/documentos"              # .../:id (si alguna vez es PDF directo)
DOCS_DESCARGAR   = f"{NEST_BASE}/api/documentos/descargar"    # <-- ESTE devuelve JSON de ticket
VENTAS_GET       = f"{NEST_BASE}/api/ventas"                  # .../:id


API.update({
    "meds_search": f"{NEST_BASE}/api/medicamentos/all",  # si existe en Nest
    "meds_all":    API.get("meds_all") or f"{NEST_BASE}/api/medicamentos/all", # recomendado
    "prov_search":   f"{NEST_BASE}/api/proveedores/all",
    "orders_search": f"{NEST_BASE}/api/pedidos",
    "ventas_search": f"{NEST_BASE}/api/ventas/search",
    "ventas_all":    f"{NEST_BASE}/api/ventas",               # fallback
})

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

def _patch(request, url, payload):
    try:
        r = requests.patch(url, json=payload, headers=_auth_headers(request), timeout=10)
        if r.status_code == 401:
            return "unauthorized", None
        return None, r
    except requests.RequestException:
        return None, None

def _strip_accents(s: str) -> str:
    return ''.join(c for c in unicodedata.normalize('NFD', s or '') if unicodedata.category(c) != 'Mn')


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
    filtro = request.GET.get('filtro', '')
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

    # FILTRO sobre la lista
    if filtro == 'stock':
        meds = [m for m in meds if (m.get("stock") or 0) > 0]
    elif filtro == 'sin_stock':
        meds = [m for m in meds if (m.get("stock") or 0) <= 0]
    elif filtro == 'caducar':
        hoy = date.today()
        proximos = hoy + timedelta(days=90)
        meds = [m for m in meds if m.get("caducidad") and hoy <= _parse_date(m.get("caducidad")) <= proximos]

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


# =========================
# Pedidos (UI)
# =========================
def orders_view(request):
    """
    Renderiza la página de Pedidos. La tabla se llena vía fetch
    contra los endpoints JSON de abajo (proxy a Nest).
    """
    return render(request, "core/orders.html", {"orders": []})


# =========================
# Pedidos (JSON / proxy)
# =========================
def orders_list_json(request):
    """GET -> lista de pedidos (proxy a Nest)."""
    err, data = _get(request, API["orders_list"])
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)
    return JsonResponse(data if isinstance(data, list) else [], safe=False)


def order_detail_json(request, order_id: int):
    """GET -> detalle de pedido (proxy a Nest)."""
    err, data = _get(request, f"{API['orders_detail']}/{order_id}")
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)
    return JsonResponse(data or {}, safe=False)


@csrf_exempt
def order_create_json(request):
    """POST -> crear pedido (proxy a Nest). Espera payload:
    {
      "proveedorId": number,
      "farmaciaId": number,
      "items": [{ "medicamentoId": n, "cantidad": n, "precioUnitario": n }]
    }"""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)

    try:
        payload = json.loads(request.body or "{}")
    except Exception:
        return JsonResponse({"error": "invalid json"}, status=400)

    if not payload.get("items"):
        return JsonResponse({"error": "el pedido requiere items"}, status=400)

    err, r = _post(request, API["orders_create"], payload)
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)
    if r and r.status_code in (200, 201):
        return JsonResponse(r.json(), status=r.status_code, safe=False)
    code = r.status_code if r else 502
    return JsonResponse({"error": "no se pudo crear", "detail": r.text if r else ""}, status=code)


@csrf_exempt
def order_patch_status_json(request, order_id: int):
    """PATCH -> cambiar estatus (proxy a Nest). Body: { "estatus": "RECIBIDO" }"""
    if request.method != "PATCH" and request.method != "POST":
        # permitimos POST por comodidad desde fetch si te es más fácil
        return JsonResponse({"error": "method not allowed"}, status=405)

    try:
        payload = json.loads(request.body or "{}")
    except Exception:
        return JsonResponse({"error": "invalid json"}, status=400)

    if payload.get("estatus") not in ("ENVIADO", "RECIBIDO", "CANCELADO"):
        return JsonResponse({"error": "estatus inválido"}, status=400)

    err, r = _patch(request, f"{API['orders_patch']}/{order_id}", payload)
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)
    if r and r.ok:
        return JsonResponse(r.json(), status=r.status_code, safe=False)
    code = r.status_code if r else 502
    return JsonResponse({"error": "no se pudo actualizar", "detail": r.text if r else ""}, status=code)

# --- Proveedores JSON (lista) ---
def proveedores_all_json(request):
    """GET -> lista de proveedores (proxy a Nest)."""
    err, data = _get(request, API["prov_all"])  # ya lo tienes mapeado a Nest /api/proveedores/all
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)
    return JsonResponse(data if isinstance(data, list) else [], safe=False)


# =========================
# Catálogos usados por el modal
# =========================
def farmacias_json(request):
    """GET -> lista de farmacias (proxy a Nest)."""
    err, data = _get(request, API["farm_all"])
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)
    return JsonResponse(data if isinstance(data, list) else [], safe=False)


def proveedor_medicamentos_json(request, prov_id: int):
    """GET -> medicamentos de un proveedor (proxy a Nest)."""
    err, data = _get(request, f"{API['prov_meds']}/{prov_id}/medicamentos")
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)
    return JsonResponse(data if isinstance(data, list) else [], safe=False)


#=======================================
#Buscador
#=======================================
def search_inventory(request):
    
    q = (request.GET.get('q') or '').strip()
    if len(q) < 2:
        return JsonResponse({'results': []})

    q_norm = _strip_accents(q).lower()
    results = []

    # -------- helpers internos ----------
    def _safe_list(data):
        if isinstance(data, list): 
            return data
        if isinstance(data, dict) and 'items' in data and isinstance(data['items'], list):
            return data['items']
        if isinstance(data, dict) and 'data' in data and isinstance(data['data'], list):
            return data['data']
        return []

    def _fetch(url_key, alt_url_key=None, limit=None, params=None):
        url = API.get(url_key)
        data = []
        if url:
            if params:
                url = f"{url}?{urllib.parse.urlencode(params)}"
            err, data = _get(request, url)
            if err == "unauthorized":
                return "unauthorized", []
        if (not _safe_list(data)) and alt_url_key:
            # fallback sin /search
            alt = API.get(alt_url_key)
            if alt:
                err, data = _get(request, alt)
                if err == "unauthorized":
                    return "unauthorized", []
        items = _safe_list(data)
        return None, (items[:limit] if (limit and isinstance(items, list)) else items)

    # ============ Medicamentos ============
    err, meds = _fetch(
        'meds_search', alt_url_key='meds_all', limit=120,
        params={'q': q, 'limit': 12}
    )
    if err == "unauthorized":
        return JsonResponse({'error': 'unauthorized'}, status=401)

    # si vino de /all, filtra localmente con tolerancia a acentos
    if API.get('meds_search') and meds and len(meds) <= 12:
        meds_filtered = meds
    else:
        meds_filtered = [
            m for m in meds
            if (q_norm in _strip_accents((m.get('nombre') or '')).lower()) 
            or (q in (m.get('lote') or '')) 
            or (q_norm in _strip_accents(str(m.get('codigo') or '')).lower())
        ][:6]

    for m in meds_filtered[:6]:
        categoria = m.get('categoria')
        proveedor = m.get('proveedor')
        results.append({
            'type': 'Medicamento',
            'label': m.get('nombre') or '—',
            'sub': f"Lote: {m.get('lote') or '—'} · Cat: {(categoria.get('nombre') if isinstance(categoria, dict) else categoria) or '—'} · Prov: {(proveedor.get('nombre') if isinstance(proveedor, dict) else proveedor) or '—'}",
            'extra': f"Stock: {m.get('stock', 0)}",
            'url': f"/inventario/medicamentos/{m.get('id') or m.get('_id')}/detalle"
        })

    # ============ Proveedores ============
    err, provs = _fetch(
        'prov_search', alt_url_key='prov_all', limit=100,
        params={'q': q, 'limit': 8}
    )
    if err == "unauthorized":
        return JsonResponse({'error': 'unauthorized'}, status=401)

    if API.get('prov_search') and provs and len(provs) <= 8:
        provs_filtered = provs
    else:
        provs_filtered = [
            p for p in provs
            if (q_norm in _strip_accents((p.get('nombre') or '')).lower())
               or (q_norm in _strip_accents((p.get('razonSocial') or '')).lower())
               or (q_norm in _strip_accents((p.get('contacto') or '')).lower())
        ][:4]

    for p in provs_filtered[:4]:
        results.append({
            'type': 'Proveedor',
            'label': p.get('nombre') or p.get('razonSocial') or '—',
            'sub': f"Contacto: {p.get('contacto') or '—'}",
            'extra': None,
            'url': f"/inventario/proveedores/{p.get('id') or p.get('_id')}"
        })

    # ============ Pedidos ============
    err, peds = _fetch(
        'orders_search', alt_url_key='orders_list', limit=120,
        params={'q': q, 'limit': 8}
    )
    if err == "unauthorized":
        return JsonResponse({'error': 'unauthorized'}, status=401)

    if API.get('orders_search') and peds and len(peds) <= 8:
        peds_filtered = peds
    else:
        peds_filtered = [
            pd for pd in peds
            if (q_norm in _strip_accents((str(pd.get('folio') or '')).lower()))
               or (q_norm in _strip_accents((str(pd.get('estado') or '')).lower()))
               or (q_norm in _strip_accents(((pd.get('proveedor') or {}).get('nombre') if isinstance(pd.get('proveedor'), dict) else str(pd.get('proveedor') or '')).lower()))
        ][:4]

    for pd in peds_filtered[:4]:
        prov = pd.get('proveedor')
        prov_nombre = (prov.get('nombre') if isinstance(prov, dict) else prov) or '—'
        total = pd.get('total')
        results.append({
            'type': 'Pedido',
            'label': f"Folio {pd.get('folio') or '—'}",
            'sub': f"Proveedor: {prov_nombre} · Estado: {pd.get('estado') or '—'}",
            'extra': (f"${float(total):.2f}" if total is not None else None),
            'url': f"/pedidos/{pd.get('id') or pd.get('_id')}"
        })

    # ============ Ventas ============
    err, ventas = _fetch(
        'ventas_search', alt_url_key='ventas_all', limit=120,
        params={'q': q, 'limit': 8}
    )
    if err == "unauthorized":
        return JsonResponse({'error': 'unauthorized'}, status=401)

    if API.get('ventas_search') and ventas and len(ventas) <= 8:
        ventas_filtered = ventas
    else:
        ventas_filtered = [
            v for v in ventas
            if (q_norm in _strip_accents((str(v.get('folio') or '')).lower()))
               or (q_norm in _strip_accents((str(v.get('cliente') or '')).lower()))
        ][:4]

    for v in ventas_filtered[:4]:
        fecha = v.get('fecha')
        fecha_txt = (fecha[:10] if isinstance(fecha, str) and len(fecha) >= 10 else '—')
        results.append({
            'type': 'Venta',
            'label': f"Folio {v.get('folio') or '—'}",
            'sub': f"Cliente: {v.get('cliente') or '—'} · Fecha: {fecha_txt}",
            'extra': f"${float(v.get('total', 0) or 0):.2f}",
            'url': f"/ventas/{v.get('id') or v.get('_id')}"
        })

    # Prioridad: Medicamento > Proveedor > Pedido > Venta
    order = {'Medicamento': 0, 'Proveedor': 1, 'Pedido': 2, 'Venta': 3}
    results.sort(key=lambda r: order.get(r['type'], 9))

    return JsonResponse({'results': results[:12]})

    q = (request.GET.get('q') or '').strip()
    results = []
    if len(q) < 2:
        return JsonResponse({'results': results})

    # Medicamentos: nombre, lote, código
    meds = (Medicamento.objects
            .filter(Q(nombre__icontains=q) | Q(lote__icontains=q) | Q(codigo__icontains=q))
            .select_related('categoria', 'proveedor')[:6])
    for m in meds:
        results.append({
            'type': 'Medicamento',
            'label': f'{m.nombre}',
            'sub': f'Lote: {m.lote} · Cat: {getattr(m.categoria,"nombre","—")} · Prov: {getattr(m.proveedor,"nombre","—")}',
            'extra': f'Stock: {m.stock}',
            'url': f'/inventario/medicamentos/{m.id}/detalle'
        })

    # Proveedores: nombre, rfc, contacto
    provs = (Proveedor.objects
             .filter(Q(nombre__icontains=q) | Q(rfc__icontains=q) | Q(contacto__icontains=q))[:4])
    for p in provs:
        results.append({
            'type': 'Proveedor',
            'label': p.nombre,
            'sub': f'RFC: {getattr(p,"rfc","—")} · Contacto: {getattr(p,"contacto","—")}',
            'extra': None,
            'url': f'/inventario/proveedores/{p.id}'
        })

    # Pedidos: folio, estado
    peds = (Pedido.objects
            .filter(Q(folio__icontains=q) | Q(estado__icontains=q) | Q(proveedor__nombre__icontains=q))
            .select_related('proveedor')[:4])
    for pd in peds:
        results.append({
            'type': 'Pedido',
            'label': f'Folio {pd.folio}',
            'sub': f'Proveedor: {getattr(pd.proveedor,"nombre","—")} · Estado: {pd.estado}',
            'extra': getattr(pd, 'total', None) and f'${pd.total:.2f}',
            'url': f'/pedidos/{pd.id}'
        })

    # Ventas: folio, paciente/cliente
    vts = (Venta.objects
           .filter(Q(folio__icontains=q) | Q(cliente__icontains=q))
           .order_by('-fecha')[:4])
    for v in vts:
        results.append({
            'type': 'Venta',
            'label': f'Folio {v.folio}',
            'sub': f'Cliente: {getattr(v,"cliente","—")} · Fecha: {v.fecha:%Y-%m-%d}',
            'extra': f'${getattr(v,"total",0):.2f}',
            'url': f'/ventas/{v.id}'
        })

    # Ordenar por prioridad sencilla (Medicamento > Proveedor > Pedido > Venta)
    order = {'Medicamento':0,'Proveedor':1,'Pedido':2,'Venta':3}
    results.sort(key=lambda r: order.get(r['type'], 9))

    # Responder
    return JsonResponse({'results': results[:12]})

def search_meds(request):
    # Requiere JWT en sesión para consultar Nest
    if not request.session.get("jwt"):
        # permitimos filtro local desde el front (devolvemos vacío → activa fallback JS)
        return JsonResponse({"results": []}, status=401)

    q = (request.GET.get('q') or '').strip()
    if len(q) < 2:
        return JsonResponse({'results': []})
    q_norm = _strip_accents(q).lower()

    # 1) Intenta /search en Nest con límite
    url = API.get('meds_search')
    if url:
        err, data = _get(request, f"{url}?{urllib.parse.urlencode({'q': q, 'limit': 12})}")
        if err != "unauthorized" and isinstance(data, (list, dict)):
            items = data if isinstance(data, list) else data.get('items') or data.get('data') or []
            results = []
            for m in items[:12]:
                cat = m.get('categoria')
                prov = m.get('proveedor')
                results.append({
                    'type': 'Medicamento',
                    'label': m.get('nombre') or '—',
                    'sub': f"Lote: {m.get('lote') or '—'} · Cat: {(cat.get('nombre') if isinstance(cat, dict) else cat) or '—'} · Prov: {(prov.get('nombre') if isinstance(prov, dict) else prov) or '—'}",
                    'extra': f"Stock: {m.get('stock', 0)}",
                    'url': f"/inventario/detalle/{m.get('id') or m.get('_id')}/",
                })
            return JsonResponse({'results': results})

    # 2) Fallback: /all y filtramos aquí
    err, data = _get(request, API['meds_all'])
    if err == "unauthorized":
        return JsonResponse({'results': []}, status=401)

    meds = data if isinstance(data, list) else data.get('data', [])
    filtered = [
        m for m in meds
        if (q_norm in _strip_accents((m.get('nombre') or '')).lower())
        or (q in (m.get('lote') or ''))
        or (q_norm in _strip_accents(str(m.get('codigo') or '')).lower())
    ][:12]

    results = []
    for m in filtered:
        cat = m.get('categoria'); prov = m.get('proveedor')
        results.append({
            'type': 'Medicamento',
            'label': m.get('nombre') or '—',
            'sub': f"Lote: {m.get('lote') or '—'} · Cat: {(cat.get('nombre') if isinstance(cat, dict) else cat) or '—'} · Prov: {(prov.get('nombre') if isinstance(prov, dict) else prov) or '—'}",
            'extra': f"Stock: {m.get('stock', 0)}",
            'url': f"/inventario/detalle/{m.get('id') or m.get('_id')}/",
        })
    return JsonResponse({'results': results})




#=====================================
#Reportes PDF
#=====================================

# Lista por tipo (opcional si lo usas en la UI)
def docs_by_tipo_json(request, tipo: str):
    err, data = _get(request, f"{DOCS_LIST}?tipo={tipo}")
    if err == "unauthorized":
        return JsonResponse({"error":"unauthorized"}, status=401)
    return JsonResponse(data if isinstance(data, list) else [], safe=False)

# Descarga/stream directo (si alguna vez Nest devuelve PDF real en /api/documentos/:id)
def doc_by_id_stream(request, doc_id: str):
    try:
        r = requests.get(f"{DOCS_FILE}/{doc_id}", headers=_auth_headers(request), timeout=20, stream=True)
        if r.status_code == 401:
            return JsonResponse({"error":"unauthorized"}, status=401)
        ct = r.headers.get("content-type", "application/octet-stream")
        resp = HttpResponse(r.content, content_type=ct)
        cd = r.headers.get("content-disposition")
        if cd:
            resp["Content-Disposition"] = cd
        return resp
    except requests.RequestException as e:
        return JsonResponse({"error":"upstream_error","detail":str(e)}, status=502)

# **NUEVO**: Ticket JSON (lo que mostraste)
def doc_descargar_json(request, doc_id: str):
    """Proxy de /api/documentos/descargar/:id — devuelve JSON del ticket."""
    err, data = _get(request, f"{DOCS_DESCARGAR}/{doc_id}")
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)
    return JsonResponse(data or {}, safe=False)

# Detalle de venta por ID (para fallbacks de jsPDF si lo necesitaras)
def venta_detalle_json(request, venta_id: str):
    err, data = _get(request, f"{VENTAS_GET}/{venta_id}")
    if err == "unauthorized":
        return JsonResponse({"error":"unauthorized"}, status=401)
    return JsonResponse(data or {}, safe=False)

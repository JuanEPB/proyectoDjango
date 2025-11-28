# views.py
import json
from datetime import datetime, date, timedelta
import base64
from collections import Counter
import requests
import unicodedata
import urllib.parse

from django.http import JsonResponse, HttpResponse, HttpResponseBadRequest
from django.shortcuts import render, redirect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib import messages, auth
from core.decorators import login_required_custom
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.views.decorators.http import require_http_methods 

from django.conf import settings
from api_client import API_BASE_URL  
from django.core.mail import send_mail
from django.core.mail import BadHeaderError
import logging
import smtplib
from django.core.mail import get_connection, EmailMessage, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.core.cache import cache
from django.core.validators import validate_email
from functools import wraps
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)

# =========================
# Config
# =========================

NEST_BASE = settings.API_URL

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
    "prov_list":   f"{NEST_BASE}/api/proveedores/all",
    "prov_create": f"{NEST_BASE}/api/proveedores/create/",          # POST
    "prov_detail": f"{NEST_BASE}/api/proveedores",          # /:id
    "prov_update": f"{NEST_BASE}/api/proveedores/update/",  # /:id
    "prov_delete": f"{NEST_BASE}/api/proveedores/delete/",  # /:id
    "venta":        f"{NEST_BASE}/api/venta",
    "cats_all":     f"{NEST_BASE}/api/categorias/all",
    "farm_all":     f"{NEST_BASE}/api/farmacia",



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
    "prov_search": f"{NEST_BASE}/api/proveedores/all",
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
    # El content-type se añade en las funciones _post, _put, _patch
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers

def _get(request, url, params=None):
    try:
        # Añadir parámetros a la URL si existen
        if params:
            # Filtra valores None o vacíos
            filtered_params = {k: v for k, v in params.items() if v is not None and v != ''}
            url = f"{url}?{urllib.parse.urlencode(filtered_params)}"
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
        headers = _auth_headers(request)
        headers['Content-Type'] = 'application/json'
        logger.info("POST -> %s payload=%s", url, payload)
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        if r.status_code == 401:
            return "unauthorized", None
        return None, r
    except requests.RequestException as e:
        logger.exception("Error llamando POST %s: %s", url, e)

        class DummyResponse:
            ok = False
            status_code = 502
            text = str(e)
        return None, DummyResponse()


def _put(request, url, payload):
    try:
        headers = _auth_headers(request)
        headers['Content-Type'] = 'application/json'

        logger.info("PUT -> %s", url)
        r = requests.put(url, json=payload, headers=headers, timeout=10)

        if r.status_code == 401:
            return "unauthorized", None

        return None, r
    except requests.RequestException as e:
        logger.exception("Error llamando PUT %s: %s", url, e)

        # Devolvemos un objeto similar a Response para que la vista no truene
        class DummyResponse:
            ok = False
            status_code = 502
            text = str(e)
        return None, DummyResponse()


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
        headers = _auth_headers(request)
        headers['Content-Type'] = 'application/json'
        r = requests.patch(url, json=payload, headers=headers, timeout=10)
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
@csrf_exempt
@require_POST
def bridge_clear_token(request):
    """
    Limpia completamente la sesión de Django.
    """
    try:
        # Flush completo de sesión
        request.session.flush()
        
        # Asegurar que la cookie se elimine
        response = JsonResponse({"ok": True})
        response.delete_cookie('sessionid')
        return response
    except Exception as e:
        logger.error(f"Error clearing session: {e}")
        return JsonResponse({"ok": False, "error": str(e)}, status=500)


@require_POST
@csrf_exempt
def bridge_store_token(request):
    """
    Guarda el accessToken en la sesión de Django y extrae el rol del usuario.
    """
    try:
        data = json.loads(request.body or "{}")
        token = data.get("accessToken")
        if not token:
            return HttpResponseBadRequest("no token")

        # Guardar en sesión
        request.session["jwt"] = token

        # --- INICIO DE LA SOLUCIÓN ---
        # Decodificar el payload del JWT para obtener el rol
        try:
            # Un JWT tiene 3 partes separadas por '.'. El payload es la segunda.
            payload_b64 = token.split('.')[1]
            # El payload en base64 puede no tener el padding correcto, lo añadimos.
            payload_b64 += '=' * (-len(payload_b64) % 4)
            # Decodificamos de base64 a bytes, y luego de bytes a string (utf-8)
            payload_json = base64.b64decode(payload_b64).decode('utf-8')
            # Parseamos el string JSON a un diccionario de Python
            payload_data = json.loads(payload_json)
            # Guardamos el rol en la sesión. Asumimos que el campo se llama 'rol'.
            request.session["user_role"] = payload_data.get("rol")
        except Exception as e:
            # Si falla la decodificación, no asignamos rol y lo registramos.
            logger.error(f"Error decodificando JWT para obtener rol: {e}")
            request.session["user_role"] = None
        # --- FIN DE LA SOLUCIÓN ---

        request.session.modified = True
        return JsonResponse({"ok": True})
    except Exception as e:
        logger.error(f"Error storing token: {e}")
        return JsonResponse({"ok": False, "error": str(e)}, status=400)


# =========================
# Decoradores de Seguridad
# =========================
def role_required(*roles):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.session.get("jwt"):
                return redirect("login")
            user_role = request.session.get("user_role")
            if user_role not in roles:
                messages.error(request, "No tienes permiso para acceder a esta página.")
                return redirect("medicamentos") # Redirigir al dashboard por defecto
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
# =========================
# Public Pages (Home, etc.)
# =========================
def home_view(request):
    """
    Renderiza la página de inicio pública (landing page).
    """
    return render(request, "core/Home.html")


@require_POST
def contact_view(request):
    """Procesa el formulario de contacto público y envía un email al administrador.

    Protecciones incluidas:
    - Honeypot (campo oculto `hp` en el formulario)
    - Validación básica de email
    - Rate-limit por IP usando cache (5 mensajes / hora)
    - Envío multipart (text + HTML) con `Reply-To` al email del cliente
    - Fallback a consola si falla la autenticación SMTP
    """
    name = (request.POST.get('name') or '').strip()
    email = (request.POST.get('email') or '').strip()
    message = (request.POST.get('message') or '').strip()
    honeypot = (request.POST.get('hp') or '').strip()

    # Honeypot: si tiene contenido, tratamos como spam silenciosamente
    if honeypot:
        logger.info('Contact form honeypot triggered; dropping submission')
        return redirect('home')

    if not (name and email and message):
        messages.error(request, 'Por favor completa todos los campos del formulario de contacto.')
        return redirect('home')

    # Validar email del remitente (cliente)
    try:
        validate_email(email)
    except ValidationError:
        messages.error(request, 'Por favor ingresa un correo válido.')
        return redirect('home')

    # Rate-limit simple por IP: 5 envíos por hora
    ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', 'unknown')).split(',')[0].strip()
    rl_key = f"contact_rl:{ip}"
    try:
        count = cache.get(rl_key)
        if count is None:
            cache.set(rl_key, 1, timeout=3600)
            count = 1
        else:
            try:
                cache.incr(rl_key)
                count = cache.get(rl_key)
            except Exception:
                # some cache backends may not support incr on missing keys concurrently
                cache.set(rl_key, int(count) + 1, timeout=3600)
                count = cache.get(rl_key)
        if int(count) > 5:
            messages.error(request, 'Has enviado demasiados mensajes. Intenta nuevamente más tarde.')
            return redirect('home')
    except Exception:
        # Si falla el cache por alguna razón, no bloqueamos el envío, solo lo registramos
        logger.exception('Error checking rate limit cache for contact form')

    subject = f"Contacto Pharmacontrol: {name}"

    # Recipient(s)
    recipient = [getattr(settings, 'CONTACT_RECIPIENT', None) or 'pharmacontrolcc@gmail.com']
    from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'webmaster@localhost')

    # Render templates for text and HTML bodies
    context = {
        'name': name,
        'email': email,
        'message': message,
        'site_name': getattr(settings, 'SITE_NAME', 'Pharmacontrol'),
        'logo_url': (request.build_absolute_uri(settings.STATIC_URL + 'img/logo.png') if getattr(settings, 'STATIC_URL', None) else None),
    }
    text_body = render_to_string('core/emails/contact_email.txt', context)
    html_body = render_to_string('core/emails/contact_email.html', context)

    try:
        conn = get_connection()
        msg = EmailMultiAlternatives(subject, text_body, from_email, recipient, connection=conn, reply_to=[email])
        msg.attach_alternative(html_body, 'text/html')
        # Optional BCC if configured
        bcc = getattr(settings, 'CONTACT_BCC', None)
        if bcc:
            if isinstance(bcc, (list, tuple)):
                msg.bcc = list(bcc)
            else:
                msg.bcc = [bcc]
        msg.send(fail_silently=False)
        messages.success(request, 'Gracias — tu mensaje ha sido enviado. Responderemos pronto.')
    except BadHeaderError:
        logger.exception('BadHeaderError sending contact email')
        messages.error(request, 'Encabezado inválido en el mensaje.')
    except Exception as e:
        logger.exception('Unexpected error sending contact email')
        # Detect SMTP auth error and fallback to console backend for local testing
        if isinstance(e, smtplib.SMTPAuthenticationError) or (hasattr(e, 'smtp_code') and getattr(e, 'smtp_code', None) == 535):
            try:
                conn = get_connection('django.core.mail.backends.console.EmailBackend')
                fallback = EmailMessage(subject, text_body, from_email, recipient, connection=conn)
                fallback.attach_alternative(html_body, 'text/html')
                fallback.send(fail_silently=False)
                messages.success(request, 'No fue posible enviar mediante SMTP; el mensaje se imprimió en la consola para pruebas.')
                logger.warning('Fell back to console email backend due to SMTP authentication error')
            except Exception:
                logger.exception('Fallback to console backend failed')
                messages.error(request, 'No fue posible enviar el mensaje. Intenta nuevamente más tarde.')
        else:
            messages.error(request, 'No fue posible enviar el mensaje. Intenta nuevamente más tarde.')

    return redirect('home')

def register_view(request):
    """
    Placeholder for registration page. Redirects to home for now.
    """
    # Later, this will render the registration form.
    # For now, we redirect to prevent errors on the home page.
    return redirect("home")


# =========================
# Login / Logout (UI)
# =========================
def login_view(request):
    """
    Renderiza la página de login.
    La lógica de autenticación y redirección post-login es manejada
    completamente por el JavaScript del lado del cliente (dashboard.js).
    """

    # Para todos los demás (no logueados, vendedores, etc.), muestra el login.
    # El JS se encargará de la autenticación y de la redirección post-login.
    return render(request, "core/login.html")

@require_POST
@csrf_exempt # El logout desde JS no enviará token CSRF
def logout_view(request):
    """
    Endpoint de logout para Django. Destruye la sesión completa.
    Es un alias/fallback para bridge_clear_token.
    """
    try:
        request.session.flush()
    except Exception: pass
    return render(request, "core/login.html")

# =========================
# Dashboard / Medicamentos
# =========================


@role_required("admin", "usuario")
def medicamentos_view(request):
    err, meds = _get(request, API["meds_all"])
    if err == "unauthorized":
        return redirect("login")
    meds = meds if isinstance(meds, list) else []

    if not meds:
        messages.warning(request, 'No se pudieron cargar los datos de los medicamentos. La API no devolvió información o no hay medicamentos registrados.')

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
# =========================
# Inventory (lista + paginación)
# =========================
@role_required("admin")
def inventory_view(request):
    # 1) Obtener lista de medicamentos
    err, meds = _get(request, API["meds_all"])
    if err == "unauthorized":
        return redirect("login")
    meds = meds if isinstance(meds, list) else []

    if not meds:
        messages.warning(
            request,
            'No se pudieron cargar los datos de los medicamentos. '
            'La API no devolvió información o no hay medicamentos registrados.'
        )

    # 2) Filtro por querystring
    filtro = request.GET.get('filtro', 'all')

    # 3) Obtener total de medicamentos
    err_count, count_data = _get(request, API["meds_count"])
    if err_count == "unauthorized":
        return redirect("login")

    total_medicamentos = 0
    if isinstance(count_data, dict):
        for v in count_data.values():
            if isinstance(v, int):
                total_medicamentos = v
                break

    # === KPIs ===
    hoy = date.today()
    caducados = 0
    por_caducar = 0
    stock_critico = 0
    medicamento_agotado = 0

    for m in meds:
        stock = m.get("stock") or 0
        d = _parse_date(m.get("caducidad"))

        if stock <= 0:
            medicamento_agotado += 1
        elif stock < 10:
            stock_critico += 1

        if d:
            if d < hoy:
                caducados += 1
            else:
                # Próximos a caducar (90 días)
                if hoy <= d <= hoy + timedelta(days=90):
                    por_caducar += 1

    # 4) Aplicar filtro sobre la lista
    if filtro == 'stock':
        meds = [m for m in meds if (m.get("stock") or 0) > 0]
    elif filtro == 'sin_stock':
        meds = [m for m in meds if (m.get("stock") or 0) <= 0]
    elif filtro == 'caducar':
        proximos = hoy + timedelta(days=90)
        meds = [
            m for m in meds
            if m.get("caducidad")
            and hoy <= _parse_date(m.get("caducidad")) <= proximos
        ]
    # si filtro == 'all' no se modifica la lista

    # 5) Paginación
    paginator = Paginator(meds, 10)
    page_number = request.GET.get("page", 1)
    try:
        page_obj = paginator.page(page_number)
    except PageNotAnInteger:
        page_obj = paginator.page(1)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)

    # Catálogos para el modal
    _, proveedores = _get(request, API["prov_list"])
    _, categorias  = _get(request, API["cats_all"])

    context = {
        "inventory": page_obj.object_list,
        "page_obj": page_obj,
        "total_medicamentos": total_medicamentos,
        "por_caducar": por_caducar,
        "stock_critico": stock_critico,
        "medicamento_agotado": medicamento_agotado,
        "pedidos_pendientes": 0,  # por si luego lo conectas con pedidos reales
        "proveedores": proveedores if isinstance(proveedores, list) else [],
        "categorias": categorias if isinstance(categorias, list) else [],
    }

    return render(request, "core/inventory.html", context)


# Crear medicamento (desde el modal del inventario)
@role_required("admin")
def create_medicamento_view(request):
    # Esta vista solo debe usarse para POST del modal
    if request.method != "POST":
        return redirect("inventory")

    # Lectura y saneo de datos
    nombre = (request.POST.get("nombre") or "").strip()
    lote = (request.POST.get("lote") or "").strip()
    caducidad = request.POST.get("caducidad") or ""

    # stock
    try:
        stock = int(request.POST.get("stock") or 0)
    except ValueError:
        stock = 0

    # precio
    try:
        precio = float(request.POST.get("precio") or 0)
    except ValueError:
        precio = 0.0

    proveedor_id = request.POST.get("proveedor_id")
    categoria_id = request.POST.get("categoria_id")

    payload = {
        "nombre": nombre,
        "lote": lote,
        "caducidad": caducidad,
        "stock": stock,
        "precio": precio,
        # IMPORTANTE: usar los nombres que espera la API
        "proveedorId": int(proveedor_id) if proveedor_id else None,
        "categoriaId": int(categoria_id) if categoria_id else None,
    }

    err, resp = _post(request, API["meds_create"], payload)

    if err == "unauthorized":
        return redirect("login")

    if resp and resp.status_code in (200, 201):
        messages.success(request, "Medicamento creado correctamente.")
    else:
        status = resp.status_code if resp else "sin respuesta de la API"
        messages.error(request, f"Error al crear medicamento ({status}).")

    return redirect("inventory")


# Editar medicamento
@role_required("admin")
def edit_medicamento_view(request, med_id):
    # 1) Traer detalle del medicamento desde Nest
    detail_url = f"{API['meds_get']}/{med_id}"  # /api/medicamentos/:id
    err, medicamento = _get(request, detail_url)
    if err == "unauthorized":
        return redirect("login")
    if not isinstance(medicamento, dict):
        messages.error(request, "No se pudo cargar la información del medicamento.")
        return redirect("inventory")

    # 2) Catálogos para selects (proveedores y categorías)
    _, proveedores = _get(request, API["prov_list"])
    _, categorias  = _get(request, API["cats_all"])
    proveedores = proveedores if isinstance(proveedores, list) else []
    categorias  = categorias if isinstance(categorias, list) else []

    if request.method == "POST":
        # Lectura y saneo de datos del form
        nombre = (request.POST.get("nombre") or "").strip()
        lote = (request.POST.get("lote") or "").strip()
        caducidad = request.POST.get("caducidad") or ""

        try:
            stock = int(request.POST.get("stock") or 0)
        except ValueError:
            stock = 0

        try:
            precio = float(request.POST.get("precio") or 0)
        except ValueError:
            precio = 0.0

        proveedor_id = request.POST.get("proveedor_id")
        categoria_id = request.POST.get("categoria_id")

        payload = {
            "nombre": nombre,
            "lote": lote,
            "caducidad": caducidad,
            "stock": stock,
            "precio": precio,
            # Nombres que espera tu API Nest
            "proveedorId": int(proveedor_id) if proveedor_id else None,
            "categoriaId": int(categoria_id) if categoria_id else None,
        }

        # 3) Actualizar en Nest
        update_url = f"{API['meds_update']}/{med_id}"  # /api/medicamentos/update/:id
        err_upd, resp = _put(request, update_url, payload)

        if err_upd == "unauthorized":
            return redirect("login")

        if resp and resp.status_code in (200, 204):
            messages.success(request, "Medicamento actualizado correctamente.")
            return redirect("inventory")  # o detalle_medicamento si prefieres
        else:
            status = resp.status_code if resp else "sin respuesta de la API"
            messages.error(request, f"Error al actualizar medicamento ({status}).")

            # Mantener lo editado en el objeto para no perder lo que escribió el usuario
            medicamento["nombre"] = nombre
            medicamento["lote"] = lote
            medicamento["caducidad"] = caducidad
            medicamento["stock"] = stock
            medicamento["precio"] = precio
            if proveedor_id:
                medicamento["proveedor"] = medicamento.get("proveedor") or {}
                medicamento["proveedor"]["id"] = int(proveedor_id)
            if categoria_id:
                medicamento["categoria"] = medicamento.get("categoria") or {}
                medicamento["categoria"]["id"] = int(categoria_id)

    context = {
        "medicamento": medicamento,
        "proveedores": proveedores,
        "categorias": categorias,
    }
    return render(request, "core/edit_medicamento.html", context)

    # 1) Traer detalle del medicamento
    detail_url = API["meds_detail"].format(id=med_id)
    err, medicamento = _get(request, detail_url)
    if err == "unauthorized":
        return redirect("login")
    if not isinstance(medicamento, dict):
        messages.error(request, "No se pudo cargar la información del medicamento.")
        return redirect("inventory")

    # 2) Catálogos para selects
    _, proveedores = _get(request, API["prov_all"])
    _, categorias  = _get(request, API["cats_all"])
    proveedores = proveedores if isinstance(proveedores, list) else []
    categorias  = categorias if isinstance(categorias, list) else []

    if request.method == "POST":
        # Lectura y saneo
        nombre = (request.POST.get("nombre") or "").strip()
        lote = (request.POST.get("lote") or "").strip()
        caducidad = request.POST.get("caducidad") or ""

        try:
            stock = int(request.POST.get("stock") or 0)
        except ValueError:
            stock = 0

        try:
            precio = float(request.POST.get("precio") or 0)
        except ValueError:
            precio = 0.0

        proveedor_id = request.POST.get("proveedor_id")
        categoria_id = request.POST.get("categoria_id")

        payload = {
            "nombre": nombre,
            "lote": lote,
            "caducidad": caducidad,
            "stock": stock,
            "precio": precio,
            # muy importante: estos nombres deben coincidir con el DTO de Nest
            "proveedorId": int(proveedor_id) if proveedor_id else None,
            "categoriaId": int(categoria_id) if categoria_id else None,
        }

        update_url = API["meds_update"].format(id=med_id)
        err_upd, resp = _put(request, update_url, payload)  # o _patch/_post según tu API

        if err_upd == "unauthorized":
            return redirect("login")

        if resp and resp.status_code in (200, 204):
            messages.success(request, "Medicamento actualizado correctamente.")
            return redirect("inventory")
        else:
            status = resp.status_code if resp else "sin respuesta de la API"
            messages.error(request, f"Error al actualizar medicamento ({status}).")

            # mantener lo digitado si hubo error
            medicamento["nombre"] = nombre
            medicamento["lote"] = lote
            medicamento["caducidad"] = caducidad
            medicamento["stock"] = stock
            medicamento["precio"] = precio
            if proveedor_id:
                medicamento["proveedor"] = medicamento.get("proveedor") or {}
                medicamento["proveedor"]["id"] = int(proveedor_id)
            if categoria_id:
                medicamento["categoria"] = medicamento.get("categoria") or {}
                medicamento["categoria"]["id"] = int(categoria_id)

    context = {
        "medicamento": medicamento,
        "proveedores": proveedores,
        "categorias": categorias,
    }
    return render(request, "core/edit_medicamento.html", context)

    # 1) Traer detalle del medicamento
    detail_url = API["meds_detail"].format(id=med_id)
    err, medicamento = _get(request, detail_url)
    if err == "unauthorized":
        return redirect("login")
    if not isinstance(medicamento, dict):
        messages.error(request, "No se pudo cargar la información del medicamento.")
        return redirect("inventory")

    # 2) Traer catálogos para selects
    _, proveedores = _get(request, API["prov_all"])
    _, categorias  = _get(request, API["cats_all"])
    proveedores = proveedores if isinstance(proveedores, list) else []
    categorias  = categorias if isinstance(categorias, list) else []

    if request.method == "POST":
        # Lectura y saneo de datos
        nombre = (request.POST.get("nombre") or "").strip()
        lote = (request.POST.get("lote") or "").strip()
        caducidad = request.POST.get("caducidad") or ""

        try:
            stock = int(request.POST.get("stock") or 0)
        except ValueError:
            stock = 0

        try:
            precio = float(request.POST.get("precio") or 0)
        except ValueError:
            precio = 0.0

        proveedor_id = request.POST.get("proveedor_id")
        categoria_id = request.POST.get("categoria_id")

        payload = {
            "nombre": nombre,
            "lote": lote,
            "caducidad": caducidad,
            "stock": stock,
            "precio": precio,
            # IMPORTANTE: usar los nombres que tu API espera
            "proveedorId": int(proveedor_id) if proveedor_id else None,
            "categoriaId": int(categoria_id) if categoria_id else None,
        }

        update_url = API["meds_update"].format(id=med_id)
        err_upd, resp = _put(request, update_url, payload)  # usa _patch/_post si así está tu API

        if err_upd == "unauthorized":
            return redirect("login")

        if resp and resp.status_code in (200, 204):
            messages.success(request, "Medicamento actualizado correctamente.")
            return redirect("inventory")  # o 'detalle_medicamento', med_id si prefieres
        else:
            status = resp.status_code if resp else "sin respuesta de la API"
            messages.error(request, f"Error al actualizar medicamento ({status}).")

            # recargamos objeto en memoria con lo editado para no perder lo que el usuario escribió
            medicamento["nombre"] = nombre
            medicamento["lote"] = lote
            medicamento["caducidad"] = caducidad
            medicamento["stock"] = stock
            medicamento["precio"] = precio
            if proveedor_id:
                medicamento["proveedor"] = medicamento.get("proveedor") or {}
                medicamento["proveedor"]["id"] = int(proveedor_id)
            if categoria_id:
                medicamento["categoria"] = medicamento.get("categoria") or {}
                medicamento["categoria"]["id"] = int(categoria_id)

    context = {
        "medicamento": medicamento,
        "proveedores": proveedores,
        "categorias": categorias,
    }
    return render(request, "core/edit_medicamento.html", context)

# Eliminar medicamento
@role_required("admin")
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
@role_required("admin")
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
@role_required("admin")
def report_view(request):
    err, reports = _get(request, API["meds_all"])
    if err == "unauthorized":
        return redirect("login")
    return render(request, "core/reports.html", {"reports": reports if isinstance(reports, list) else []})

# # =========================
# # Pedidos
# # =========================
# @login_required_custom
# def order_view(request):
#     err, orders = _get(request, API["meds_all"])
#     if err == "unauthorized":
#         return redirect("login")
#     return render(request, "core/orders.html", {"orders": orders if isinstance(orders, list) else []})

# =========================
# Configuración
# =========================
@role_required("admin", "usuario")
def settings_view(request):
    err, settings = _get(request, API["meds_all"])
    if err == "unauthorized":
        return redirect("login")
    return render(request, "core/settings.html", {"settings": settings if isinstance(settings, list) else []})


# =========================
# Proveedores
# =========================
@role_required("admin")
def supplier_view(request):
    """
    Renderiza la página de proveedores. La tabla se llena dinámicamente
    vía JavaScript contra los endpoints de la API de proveedores.
    """
    return render(request, "core/suppliers.html")

# =========================
# Proveedores (API JSON)
# =========================
@role_required("admin")
def proveedores_list_create_json(request):
    """
    GET  -> lista de proveedores desde Nest
    POST -> crea proveedor en Nest
    """
    if request.method == 'GET':
        q = request.GET.get('q', None)
        status = request.GET.get('status', None)

        if status is not None:
            if status.lower() == 'true':
                status = True
            elif status.lower() == 'false':
                status = False

        params = {'q': q, 'activo': status}
        err, data = _get(request, API["prov_list"], params=params)
        if err == "unauthorized":
            return JsonResponse({"error": "unauthorized"}, status=401)

        return JsonResponse(data if isinstance(data, list) else [], safe=False)

    # ---------- CREATE ----------
    if request.method == 'POST':
        try:
            payload = json.loads(request.body or "{}")
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        # Nunca mandes id en el body
        payload.pop('id', None)

        # Campos del form
        nombre    = (payload.get('nombre') or '').strip()
        telefono  = (payload.get('telefono') or '').strip()
        email     = (payload.get('email') or '').strip()
        direccion = (payload.get('direccion') or '').strip()

        # Teléfono + email -> 'contacto' como string (lo que espera Nest)
        partes = []
        if telefono:
            partes.append(f"Teléfono: {telefono}")
        if email:
            partes.append(f"Email: {email}")
        contacto_str = ", ".join(partes) if partes else ""

        new_payload = {
            "nombre": nombre,
            "contacto": contacto_str,
            "direccion": direccion,
        }

        err, r = _post(request, API["prov_create"], new_payload)
        if err == "unauthorized":
            return JsonResponse({"error": "unauthorized"}, status=401)

        if not r or not r.ok:
            # Si Nest responde 4xx/5xx o hay error de red
            detail = None
            if r is not None:
                try:
                    detail = r.json()
                except Exception:
                    detail = r.text
            return JsonResponse(
                {"error": "Failed to create supplier", "detail": detail or "No response"},
                status=r.status_code if r else 502
            )

        # OK
        try:
            data = r.json()
        except ValueError:
            data = {}
        return JsonResponse(data, status=r.status_code)

    return JsonResponse({"error": "Method not allowed"}, status=405)

    """
    GET  -> lista de proveedores desde Nest
    POST -> crea proveedor en Nest
    """
    if request.method == 'GET':
        q = request.GET.get('q') or None
        status = request.GET.get('status') or None

        if status is not None:
            if status.lower() == 'true':
                status = True
            elif status.lower() == 'false':
                status = False

        params = {'q': q, 'activo': status}
        err, data = _get(request, API["prov_list"], params=params)

        if err == "unauthorized":
            return JsonResponse({"error": "unauthorized"}, status=401)

        return JsonResponse(data if isinstance(data, list) else [], safe=False)

    if request.method == 'POST':
        try:
            payload = json.loads(request.body or "{}")
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        # Teléfono + email -> campo 'contacto' para Nest
        telefono = payload.pop('telefono', None)
        email    = payload.pop('email', None)

        contact_parts = []
        if telefono:
            contact_parts.append(f"Teléfono: {telefono}")
        if email:
            contact_parts.append(f"Email: {email}")

        if contact_parts:
            payload['contacto'] = ", ".join(contact_parts)

        err, r = _post(request, API["prov_create"], payload)
        if err == "unauthorized":
            return JsonResponse({"error": "unauthorized"}, status=401)

        if r and r.ok:
            return JsonResponse(r.json(), status=r.status_code)

        return JsonResponse(
            {"error": "Failed to create supplier", "detail": r.text if r else "No response"},
            status=r.status_code if r else 502
        )

    return JsonResponse({"error": "Method not allowed"}, status=405)


@role_required("admin")
def proveedor_detail_json(request, id: int):
    """
    GET -> detalle de un proveedor por id (proxy a Nest)
    """
    if request.method != 'GET':
        return JsonResponse({"error": "Method not allowed"}, status=405)

    url_nest = f"{API['prov_detail']}/{id}"  # {API_URL}/api/proveedores/1

    err, data = _get(request, url_nest)
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)

    # _get devuelve directamente los datos (dict) o una lista vacía en caso de error.
    # Si data es un diccionario no vacío, la llamada fue exitosa.
    if isinstance(data, dict) and data:
        return JsonResponse(data, status=200)
    
    # Si no, hubo un error o no se encontró el proveedor.
    return JsonResponse({"error": "Failed to fetch supplier", "detail": "Not found or API error"}, status=404)


# core/views.py
@role_required("admin")
@require_http_methods(["PUT", "PATCH"])
def proveedor_update_json(request, id):
    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"detail": "JSON inválido"}, status=400)

    # No mandamos el id en el body
    payload.pop("id", None)

    # Tomamos los campos del formulario
    telefono = payload.pop("telefono", "").strip()
    email = payload.pop("email", "").strip()
    direccion = payload.get("direccion", "").strip()
    nombre = payload.get("nombre", "").strip()
    activo = payload.get("activo", True)

    # Construimos el string contacto EXACTAMENTE como en Postman
    partes = []
    if telefono:
        partes.append(f"Teléfono: {telefono}")
    if email:
        partes.append(f"Email: {email}")
    contacto_str = ", ".join(partes) if partes else ""

    payload = {
        "nombre": nombre,
        "contacto": contacto_str,
        "direccion": direccion,
        "activo": activo,
    }

    url_nest = f"{API['prov_update']}{id}"  # ej: https://api.pharmacontrol.site/api/proveedores/update/
    logger.info(f"Actualizando proveedor {id} vía {url_nest} payload={payload}")

    err, r = _put(request, url_nest, payload)
    if err or not r or not r.ok:
        detail = None
        if r is not None:
            try:
                detail = r.json()
            except Exception:
                detail = r.text
        logger.error(f"Error al actualizar proveedor {id}: err={err}, detail={detail}")
        return JsonResponse(
            {"error": "Failed to update", "detail": detail or "No response"},
            status=502,
        )

    return JsonResponse(r.json(), safe=False)


@role_required("admin")
def proveedor_delete_json(request, id: int):
    """
    DELETE -> elimina proveedor en Nest
    """
    if request.method != 'DELETE':
        return JsonResponse({"error": "Method not allowed"}, status=405)

    url_nest = f"{API['prov_delete']}{id}"  # {API_URL}/api/proveedores/delete/1

    err, r = _delete(request, url_nest)

    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)

    if r and r.ok:
        return JsonResponse({"success": True}, status=r.status_code)

    return JsonResponse(
        {"error": "Failed to delete supplier", "detail": r.text if r else "No response"},
        status=r.status_code if r else 500
    )

#========================
# Usuarios
#========================
# --- USUARIOS ---
# ========================
# Usuarios
# ========================

@role_required("admin")
def user_view(request):
    err, users = _get(request, API["users_all"])
    if err == "unauthorized":
        return redirect("login")
    return render(request, "core/users.html", {
        "users": users if isinstance(users, list) else []
    })


@role_required("admin")
def add_user_view(request):
    if request.method == "POST":
        nombre = (request.POST.get("nombre") or "").strip()
        apellido = (request.POST.get("apellido") or "").strip()
        rol = (request.POST.get("rol") or "").strip()
        email = (request.POST.get("email") or "").strip()
        contraseña = request.POST.get("contraseña") or ""
        contraseña_confirm = request.POST.get("contraseña_confirm") or ""

        form_data = {
            "nombre": nombre,
            "apellido": apellido,
            "rol": rol,
            "email": email,
        }

        if not nombre or not apellido or not rol or not email:
            error = "Todos los campos son obligatorios."
            return render(request, "core/add_user.html", {"error": error, "form": form_data})

        if len(contraseña) < 8:
            error = "La contraseña debe tener al menos 8 caracteres."
            return render(request, "core/add_user.html", {"error": error, "form": form_data})

        if contraseña != contraseña_confirm:
            error = "Las contraseñas no coinciden."
            return render(request, "core/add_user.html", {"error": error, "form": form_data})

        payload = {
            "nombre": nombre,
            "apellido": apellido,
            "rol": rol,
            "email": email,
            "contraseña": contraseña,  # la API la encripta
        }

        err, r = _post(request, API["users_create"], payload)
        if err == "unauthorized":
            return redirect("login")

        if r and r.status_code in (200, 201):
            messages.success(request, "Usuario creado correctamente.")
            return redirect("users")

        error = f"Error al crear usuario ({r.status_code if r else 'sin respuesta'})"
        return render(request, "core/add_user.html", {"error": error, "form": form_data})

    # GET
    return render(request, "core/add_user.html")


@role_required("admin")
def edit_user_view(request, user_id):
    """
    Edita un usuario existente:
    GET  -> carga datos desde la API y muestra el formulario
    POST -> envía cambios a la API y redirige a la lista
    """
    if request.method == "POST":
        nombre = (request.POST.get("nombre") or "").strip()
        apellido = (request.POST.get("apellido") or "").strip()
        rol = (request.POST.get("rol") or "").strip()
        email = (request.POST.get("email") or "").strip()

        user_obj = {
            "id": user_id,
            "nombre": nombre,
            "apellido": apellido,
            "rol": rol,
            "email": email,
        }

        if not nombre or not apellido or not rol or not email:
            error = "Todos los campos son obligatorios."
            return render(request, "core/edit_user.html", {"user": user_obj, "error": error})

        payload = {
            "nombre": nombre,
            "apellido": apellido,
            "rol": rol,
            "email": email,
            # la contraseña no se toca aquí; se haría en otra pantalla
        }

        err, r = _put(request, f"{API['users_update']}/{user_id}", payload)
        if err == "unauthorized":
            return redirect("login")

        if r and r.status_code in (200, 204):
            messages.success(request, "Usuario actualizado correctamente.")
            return redirect("users")

        error = f"No se pudo actualizar el usuario ({r.status_code if r else 'sin respuesta'})"
        return render(request, "core/edit_user.html", {"user": user_obj, "error": error})

    # GET: cargar datos desde la API
    err, u = _get(request, f"{API['users_get']}/{user_id}")
    if err == "unauthorized":
        return redirect("login")
    if not isinstance(u, dict):
        messages.error(request, "No se pudo cargar la información del usuario.")
        return redirect("users")

    return render(request, "core/edit_user.html", {"user": u})


@role_required("admin")
def delete_user_view(request, user_id):
    err, r = _delete(request, f"{API['users_delete']}/{user_id}")
    if err == "unauthorized":
        return redirect("login")

    if r and r.status_code in (200, 204):
        messages.success(request, "Usuario eliminado correctamente.")
    else:
        messages.error(request, f"No se pudo eliminar el usuario ({r.status_code if r else 'sin respuesta'})")

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

@role_required("admin", "usuario")
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

def quitar_del_carrito(request, medicamento_id):
    if request.method == "POST":
        carrito = request.session.get("carrito", [])
        carrito = [item for item in carrito if str(item["id"]) != str(medicamento_id)]
        request.session["carrito"] = carrito
    return redirect("carrito")

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
@role_required("admin")
def orders_view(request):
    """
    Renderiza la página de Pedidos. La tabla se llena vía fetch
    contra los endpoints JSON de abajo (proxy a Nest).
    """
    return render(request, "core/orders.html", {"orders": []})


# =========================
# Pedidos (JSON / proxy)
# =========================
@role_required("admin")
def orders_list_json(request):
    """GET -> lista de pedidos (proxy a Nest)."""
    err, data = _get(request, API["orders_list"])
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)

    # La API puede regresar:
    # - una lista directa: [ {...}, {...} ]
    # - o un wrapper: { "items": [...], "data": [...], "results": [...] }
    if isinstance(data, list):
        pedidos = data
    elif isinstance(data, dict):
        pedidos = (
            data.get("items")
            or data.get("data")
            or data.get("results")
            or []
        )
        if not isinstance(pedidos, list):
            pedidos = []
    else:
        pedidos = []

    return JsonResponse(pedidos, safe=False)



@role_required("admin")
def order_detail_json(request, order_id: int):
    """GET -> detalle de pedido (proxy a Nest)."""
    err, data = _get(request, f"{API['orders_detail']}/{order_id}")
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)
    return JsonResponse(data or {}, safe=False)


@role_required("admin")
def order_create_json(request):
    """POST -> crear pedido (proxy a Nest)."""
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
    return JsonResponse(
        {"error": "no se pudo crear", "detail": r.text if r else ""},
        status=code,
    )


@role_required("admin")
def order_patch_status_json(request, order_id: int):
    """
    PATCH -> cambiar estatus (proxy a Nest). Body: { "estatus": "RECIBIDO" }

    Si el nuevo estatus es RECIBIDO:
      - lee el pedido (items)
      - por cada medicamento, suma la cantidad al stock y hace PUT a /api/medicamentos/update/:id
    """
    if request.method not in ("PATCH", "POST"):
        return JsonResponse({"error": "method not allowed"}, status=405)

    try:
        payload = json.loads(request.body or "{}")
    except Exception:
        return JsonResponse({"error": "invalid json"}, status=400)

    nuevo_estatus = payload.get("estatus")
    if nuevo_estatus not in ("ENVIADO", "RECIBIDO", "CANCELADO"):
        return JsonResponse({"error": "estatus inválido"}, status=400)

    # PATCH en Nest
    err, r = _patch(request, f"{API['orders_patch']}/{order_id}", payload)
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)
    if not (r and r.ok):
        code = r.status_code if r else 502
        return JsonResponse(
            {"error": "no se pudo actualizar", "detail": r.text if r else ""},
            status=code,
        )

    try:
        pedido = r.json() or {}
    except ValueError:
        pedido = {}

    # Ajustar inventario si quedó en RECIBIDO
    if nuevo_estatus == "RECIBIDO":
        if not pedido.get("items"):
            err_det, detalle = _get(request, f"{API['orders_detail']}/{order_id}")
            if not err_det and isinstance(detalle, dict):
                pedido = detalle

        items = pedido.get("items") or []
        for it in items:
            med = it.get("medicamento")
            med_id = None
            if isinstance(med, dict):
                med_id = med.get("id") or med.get("_id")
            if not med_id:
                med_id = it.get("medicamentoId") or it.get("medicamento_id")

            cantidad = it.get("cantidad") or 0
            if not med_id or cantidad <= 0:
                continue

            # Traer medicamento actual
            err_med, med_data = _get(request, f"{API['meds_get']}/{med_id}")
            if err_med == "unauthorized" or not isinstance(med_data, dict):
                continue

            stock_actual = med_data.get("stock") or 0
            nuevo_stock = stock_actual + cantidad

            proveedor = med_data.get("proveedor")
            categoria = med_data.get("categoria")

            payload_med = {
                "nombre": med_data.get("nombre"),
                "lote": med_data.get("lote"),
                "caducidad": med_data.get("caducidad"),
                "stock": nuevo_stock,
                "precio": med_data.get("precio") or 0,
                "proveedorId": (
                    proveedor.get("id") if isinstance(proveedor, dict) else None
                ),
                "categoriaId": (
                    categoria.get("id") if isinstance(categoria, dict) else None
                ),
            }

            _put(request, f"{API['meds_update']}/{med_id}", payload_med)

    return JsonResponse(pedido, status=r.status_code, safe=False)


# --- Catálogos usados por el modal ----

@role_required("admin")
def farmacias_json(request):
    """GET -> lista de farmacias (proxy a Nest)."""
    err, data = _get(request, API["farm_all"])
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)
    return JsonResponse(data if isinstance(data, list) else [], safe=False)


@role_required("admin")
def proveedores_all_json(request):
    """GET -> lista de proveedores (proxy a Nest)."""
    err, data = _get(request, API["prov_list"])
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)
    return JsonResponse(data if isinstance(data, list) else [], safe=False)


def proveedor_medicamentos_json(request, prov_id: int):
    """
    GET -> medicamentos disponibles para un proveedor (proxy a Nest).

    1) Intenta /api/proveedores/:id/medicamentos
    2) Si viene vacío, devuelve catálogo completo de medicamentos.
    """
    # 1) meds por proveedor
    err, data = _get(request, f"{API['prov_meds']}/{prov_id}/medicamentos")
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)

    meds = []
    if isinstance(data, list):
        meds = data
    elif isinstance(data, dict):
        if isinstance(data.get("items"), list):
            meds = data["items"]
        elif isinstance(data.get("medicamentos"), list):
            meds = data["medicamentos"]

    # 2) Fallback a catálogo general
    if not meds:
        err_all, data_all = _get(request, API["meds_all"])
        if not err_all and isinstance(data_all, list):
            meds = data_all

    return JsonResponse(meds if meds else [], safe=False)

#=======================================
#Buscador
#=======================================
def search_inventory(request):
    if not request.session.get("jwt"): return JsonResponse({'results': []}, status=401)
    
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

@role_required("admin")
# Lista por tipo (opcional si lo usas en la UI)
def docs_by_tipo_json(request, tipo: str):
    err, data = _get(request, f"{DOCS_LIST}?tipo={tipo}")
    if err == "unauthorized":
        return JsonResponse({"error":"unauthorized"}, status=401)
    return JsonResponse(data if isinstance(data, list) else [], safe=False)

# Descarga/stream directo (si alguna vez Nest devuelve PDF real en /api/documentos/:id)
@role_required("admin")
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
@role_required("admin", "usuario")
def doc_descargar_json(request, doc_id: str):
    """Proxy de /api/documentos/descargar/:id — devuelve JSON del ticket."""
    err, data = _get(request, f"{DOCS_DESCARGAR}/{doc_id}")
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)
    return JsonResponse(data or {}, safe=False)

# Detalle de venta por ID (para fallbacks de jsPDF si lo necesitaras)
@role_required("admin", "usuario")
def venta_detalle_json(request, venta_id: str):
    err, data = _get(request, f"{VENTAS_GET}/{venta_id}")
    if err == "unauthorized":
        return JsonResponse({"error": "unauthorized"}, status=401)
    return JsonResponse(data or {}, safe=False)

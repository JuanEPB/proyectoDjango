
from django.contrib import admin
from django.urls import path
from core import views as core  # usamos alias para evitar confusiones

urlpatterns = [
    path('admin/', admin.site.urls),

    # Public Pages
    path('', core.home_view, name='home'),
    path('register/', core.register_view, name='register'),  # Placeholder

    # Auth
    path('login/', core.login_view, name='login'),
    path('logout/', core.logout_view, name='logout'),
    path('contact/', core.contact_view, name='contact'),

    # Dashboard / Medicamentos
    path('medicamentos/', core.medicamentos_view, name='medicamentos'),  # alias a medicamentos_view
    path('inventario/detalle/<int:medicamento_id>/', core.detalle_medicamento_view, name='detalle_medicamento'),
    path('inventario/eliminar/<int:medicamento_id>/', core.eliminar_medicamento_view, name='eliminar_medicamento'),
    path('medicamento/edit/<int:medicamento_id>/', core.edit_medicamento_view, name='edit_medicamento'),
    path('inventory/', core.inventory_view, name='inventory'),
    path('inventory/create/', core.create_medicamento_view, name='create_medicamento'),

    # Reportes / Pedidos / Config
    path('report/', core.report_view, name='reports'),
    path('order/', core.order_view, name='orders'),
    path('settings/', core.settings_view, name='settings'),  # si tienes una view específica de settings, cámbiala aquí

    # Proveedores
    path('supplier/', core.supplier_view, name='suppliers'),           # listado
    path('proveedores/', core.supplier_view, name='suppliers_alt'),    # alias opcional (borra si no lo usas)
    path('proveedores/agregar/', core.add_supplier_view, name='add_supplier'),
    path('proveedores/editar/<int:id>/', core.edit_supplier_view, name='edit_supplier'),
    path('proveedores/eliminar/<int:id>/', core.delete_supplier_view, name='delete_supplier'),

    # # Usuarios
    path('user/', core.user_view, name='users'),
    path('usuarios/agregar/', core.add_user_view, name='add_user'),
    path('usuarios/editar/<int:user_id>/', core.edit_user_view, name='edit_user'),
    path('usuarios/eliminar/<int:user_id>/', core.delete_user_view, name='delete_user'),

    # Carrito / Ventas
    path('carrito/', core.carrito_view, name='carrito'),
    path('carrito/agregar/<int:medicamento_id>/', core.agregar_al_carrito, name='agregar_al_carrito'),
    path('carrito/quitar/<int:medicamento_id>/', core.quitar_del_carrito, name='quitar_del_carrito'),
    path('carrito/compra/', core.realizar_compra, name='realizar_compra'),

    # Bridge (JS -> Django) para token en sesión
    path('bridge/store-token/', core.bridge_store_token, name='bridge_store_token'),
    path('bridge/clear-token/', core.bridge_clear_token, name='bridge_clear_token'),

      # Página
    path("orders/", core.orders_view, name="orders"),

    # JSON (proxy)
    path("orders/api/list/", core.orders_list_json, name="orders_list_json"),
    path("orders/api/<int:order_id>/", core.order_detail_json, name="order_detail_json"),
    path("orders/api/create/", core.order_create_json, name="order_create_json"),
    path("orders/api/<int:order_id>/status/", core.order_patch_status_json, name="order_patch_status_json"),
    path("orders/api/proveedores/", core.proveedores_all_json, name="proveedores_all_json"),


    # Catálogos
    path("orders/api/farmacias/", core.farmacias_json, name="farmacias_json"),
    path("orders/api/proveedores/<int:prov_id>/medicamentos/", core.proveedor_medicamentos_json, name="proveedor_medicamentos_json"),

    path('inventario/search/', core.search_inventory, name='search_inventory'),
    path('inventario/search',  core.search_inventory), 

    path('inventario/meds/search', core.search_meds, name='search_meds'),
    path('inventario/meds/search/', core.search_meds),  # compat

    # urls.py
    path('api/documentos/tipo/<str:tipo>', core.docs_by_tipo_json, name='docs_by_tipo_json'),
    path('api/documentos/<str:doc_id>',     core.doc_by_id_stream, name='doc_by_id_stream'),           # por si es PDF
    path('api/documentos/descargar/<str:doc_id>', core.doc_descargar_json, name='doc_descargar_json'),  # JSON de ticket
    path('api/ventas/<str:venta_id>',       core.venta_detalle_json, name='venta_detalle_json'),



    # Otros
    path('asda/', core.navbar, name='navbar'),
]
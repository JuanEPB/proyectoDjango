
from django.contrib import admin
from django.urls import path
from core import views as core  # usamos alias para evitar confusiones

urlpatterns = [
    path('admin/', admin.site.urls),

    # Auth
    path('login/', core.login_view, name='login'),
    path('logout/', core.logout_view, name='logout'),

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
    path('settings/', core.inventory_view, name='settings'),  # si tienes una view específica de settings, cámbiala aquí

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

    # Otros
    path('asda/', core.navbar, name='navbar'),
]

from django.contrib import admin
from django.urls import path
from core.views import eliminar_medicamento_view, inventory_view, login_view, logout_view, lista_medicamentos, report_view, user_view, order_view, supplier_view,detalle_medicamento_view, create_medicamento_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('medicamentos/', lista_medicamentos, name='medicamentos'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('inventory/', inventory_view, name='inventory'),
    path('report/', report_view, name='reports'),
    path('user/', user_view, name='users'),
    path('order/', order_view, name='orders'),
    path('supplier/', supplier_view, name='suppliers'),
    path('settings/', inventory_view, name='settings'),
    path('inventario/eliminar/<int:medicamento_id>/', eliminar_medicamento_view, name='eliminar_medicamento'),
    path('inventario/detalle/<int:medicamento_id>/', detalle_medicamento_view, name='detalle_medicamento'),
    path('inventory/create/', create_medicamento_view, name='create_medicamento'),





]




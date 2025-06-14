from django.contrib import admin
from django.urls import path
from core.views import (
    lista_medicamentos, login_view, logout_view, inventory_view, report_view,
    user_view, order_view, supplier_view, add_supplier_view
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('medicamentos/', lista_medicamentos, name='medicamentos'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('inventory/', inventory_view, name='inventory'),
    path('report/', report_view, name='reports'),
    path('user/', user_view, name='users'),
    path('order/', order_view, name='orders'),
    path('supplier/', supplier_view, name='suppliers'),  # opcional, si quieres usar dos URLs
    path('proveedores/', add_supplier_view, name='suppliers'),
    path('settings/', inventory_view, name='settings'),
    
]

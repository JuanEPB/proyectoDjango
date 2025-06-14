"""
URL configuration for pharmacontrol_django project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from core.views import lista_medicamentos, login_view, logout_view, inventory_view, report_view, user_view, order_view, supplier_view,navbar,lista_medicamentos
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
    path('asda/', navbar, name='navar'),
path('medicamentos/', lista_medicamentos, name='resumen_medicamentos'),

]

# Estructura de Ramas del Proyecto

Este proyecto utiliza las siguientes ramas para organizar el desarrollo:

## Ramas Principales

1. eature/auth-sistema
   - Manejo de autenticación y autorización
   - Login, logout y registro
   - Recuperación de contraseña

2. eature/medicamentos-crud
   - Gestión de medicamentos
   - Crear, leer, actualizar y eliminar medicamentos
   - Búsqueda y filtrado

3. eature/inventario-control
   - Control de inventario
   - Stock y movimientos
   - Alertas de inventario bajo

4. eature/reportes-sistema
   - Sistema de reportes
   - Estadísticas
   - Exportación de datos

5. eature/usuarios-gestion
   - Gestión de usuarios
   - Roles y permisos
   - Perfiles de usuario

6. eature/pedidos-sistema
   - Sistema de pedidos
   - Seguimiento de órdenes
   - Estado de pedidos

7. eature/proveedores-gestion
   - Gestión de proveedores
   - Catálogo de productos
   - Información de contacto

8. eature/configuracion-sistema
   - Configuraciones generales
   - Parámetros del sistema
   - Personalización

## Cómo Trabajar con las Ramas

1. **Clonar el repositorio:**
   `ash
   git clone https://github.com/JuanEPB/proyectoDjango.git
   `

2. **Cambiar a la rama de tu módulo:**
   `ash
   git checkout feature/nombre-modulo
   `

3. **Mantener tu rama actualizada:**
   `ash
   git checkout master
   git pull origin master
   git checkout feature/nombre-modulo
   git merge master
   `

4. **Guardar tus cambios:**
   `ash
   git add .
   git commit -m "Descripción clara del cambio"
   git push origin feature/nombre-modulo
   `

5. **Cuando termines tus cambios:**
   - Crea un Pull Request en GitHub
   - Espera la revisión del código
   - Una vez aprobado, se fusionará con master

## Reglas Importantes

1. **NO** hacer commit directamente a master
2. Mantener los commits pequeños y específicos
3. Escribir mensajes de commit descriptivos
4. Probar los cambios antes de hacer push
5. Mantener actualizada tu rama con master

## Enlaces Útiles

- Guía completa de Git: [docs/guia_git.txt](docs/guia_git.txt)
- Documentación de Django: [https://docs.djangoproject.com/](https://docs.djangoproject.com/)

## Contacto

Si tienes dudas o problemas, contacta al líder del equipo.

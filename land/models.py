from django.db import models
from django.contrib.auth.models import AbstractUser


# ==========================================================================================================================
# Modelo Usuario
# ==========================================================================================================================


class User(AbstractUser):
    nombre_completo = models.CharField(
        max_length=255, blank=False, null=False, help_text="Nombre completo"
    )
    foto_perfil = models.ImageField(null=True, blank=True, help_text="Foto Perfil")
    estatus_sistema = models.BooleanField(
        "Estatus en el Sistema",
        default=True,
        help_text="True si está activo, False si está eliminado.",
    )
    fecha_registro = models.DateTimeField(auto_now_add=True, editable=False)
    ultimo_login = models.DateTimeField(auto_now_add=True, editable=False)

    def __str__(self):
        return str(self.id) + "-" + str(self.username)


# ==========================================================================================================================
# Modelo Tarea
# ==========================================================================================================================


class Tarea(models.Model):
    nombre_tarea = models.CharField(
        max_length=255, blank=False, null=False, help_text="Nombre Tarea"
    )
    descripcion = models.TextField(blank=True, help_text="Descripción de la tarea")
    fecha_vencimiento = models.DateTimeField(
        null=True, blank=True, help_text="Fecha límite para completar la tarea"
    )
    prioridad = models.IntegerField(
        choices=[(1, "Baja"), (2, "Media"), (3, "Alta")],
        default=2,
        help_text="Nivel de prioridad de la tarea",
    )
    estado = models.CharField(
        max_length=50,
        choices=[
            ("pendiente", "Pendiente"),
            ("en_progreso", "En Progreso"),
            ("completada", "Completada"),
            ("cancelada", "Cancelada"),
        ],
        default="pendiente",
        help_text="Estado actual de la tarea",
    )
    estatus_sistema = models.BooleanField(
        "Estatus en el Sistema",
        default=True,
        help_text="True si está activo, False si está eliminado.",
    )
    fecha_elaboracion = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return str(self.id) + "-" + str(self.nombre_tarea)

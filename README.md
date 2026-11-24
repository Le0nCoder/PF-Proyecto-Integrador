# ACCESSGUARD — Prototipo IAM y Control de Acceso TECHNOVA

Prototipo funcional en Python diseñado para la asignatura **Control y Acceso de Sistemas** de la FCC-BUAP. Implementa un sistema de gestión de identidades y control de acceso para el caso de estudio **TECHNOVA**, integrando autenticación multifactor (MFA), almacenamiento seguro de credenciales, control basado en roles (RBAC), políticas contextuales basadas en atributos (ABAC), ciclo de vida IAM y bitácora de auditoría.

---

## Características principales

* **Autenticación y criptografía:**
  * Contraseñas almacenadas con `PBKDF2-HMAC-SHA256` (100,000 iteraciones y sal aleatoria de 16 bytes) y verificación en tiempo constante (`secrets.compare_digest`).
  * Segundo factor obligatorio mediante **TOTP** con `pyotp` y ventana de tolerancia `valid_window=1`.
  * Tokens de sesión criptográficamente seguros (`secrets.token_urlsafe(24)`) con expiración automática a los 30 minutos y revalidación de estado en cada petición.
* **Control basado en roles (RBAC):**
  * Verificación en el servidor para 4 roles (`Administrador`, `RecursosHumanos`, `Operador`, `Auditor`).
  * Bloqueo absoluto de `modificar_registros_auditoria` para todos los roles (segregación de funciones).
* **Control basado en atributos (ABAC):**
  * **Política 1 (Estado):** Exige `estado == "Activo"`.
  * **Política 2 (Departamento):** Para `consultar_expedientes_rrhh`, exige coincidencia exacta entre el departamento del usuario y el del recurso.
  * **Política 3 (Entorno):** Para `administrar_cuentas` y `ver_registros`, exige horario hábil (`8 <= hora <= 18`) y `red == "corporativa"`.
  * Comportamiento *fail-closed* (denegación por defecto si falta algún atributo requerido).
* **Gestión del ciclo de vida IAM:**
  * Alta de usuarios, cambio de rol (con bloqueo de autoescalamiento `actor == target_user`), actualización de departamento, concesión/revocación de permisos temporales y suspensión de cuentas con purga inmediata de sesiones activas.
* **Auditoría:**
  * Registro estructurado en memoria con marca de tiempo, actor, tipo de evento, detalle y resultado, sin almacenar contraseñas ni semillas MFA.

---

## Requisitos

* **Python 3.8+**
* Librería externa: `pyotp` (el resto utiliza módulos de la biblioteca estándar: `hashlib`, `secrets`, `os`, `time`, `datetime`).

### Instalación de dependencias

```bash
pip install pyotp

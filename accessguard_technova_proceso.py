import pyotp
import hashlib
import time
import os
import secrets
from datetime import datetime, timedelta

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ":" + pwd_hash.hex()

def verify_password(stored_password, provided_password):
    salt_hex, hash_hex = stored_password.split(":")
    salt = bytes.fromhex(salt_hex)
    new_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000).hex()
    return secrets.compare_digest(hash_hex, new_hash)

USUARIOS = {
    "ana_adm": {"nombre": "Ana Pérez", "password": hash_password("PassAdm1!"), "rol": "Administrador", "departamento": "TI", "estado": "Activo", "mfa_secret": pyotp.random_base32(), "permisos_extra": []},
    "carlos_adm": {"nombre": "Carlos Gómez", "password": hash_password("PassAdm2!"), "rol": "Administrador", "departamento": "TI", "estado": "Activo", "mfa_secret": pyotp.random_base32(), "permisos_extra": []},
    "carmen_rrhh": {"nombre": "Carmen Ruíz", "password": hash_password("PassRrhh1!"), "rol": "RecursosHumanos", "departamento": "RRHH", "estado": "Activo", "mfa_secret": pyotp.random_base32(), "permisos_extra": []},
    "david_rrhh": {"nombre": "David Torres", "password": hash_password("PassRrhh2!"), "rol": "RecursosHumanos", "departamento": "RRHH", "estado": "Activo", "mfa_secret": pyotp.random_base32(), "permisos_extra": []},
    "bruno_op": {"nombre": "Bruno López", "password": hash_password("PassOp1!"), "rol": "Operador", "departamento": "Operaciones", "estado": "Activo", "mfa_secret": pyotp.random_base32(), "permisos_extra": []},
    "elena_op": {"nombre": "Elena Morales", "password": hash_password("PassOp2!"), "rol": "Operador", "departamento": "Operaciones", "estado": "Activo", "mfa_secret": pyotp.random_base32(), "permisos_extra": []},
    "luis_aud": {"nombre": "Luis Rojas", "password": hash_password("PassAud1!"), "rol": "Auditor", "departamento": "Auditoria", "estado": "Activo", "mfa_secret": pyotp.random_base32(), "permisos_extra": []},
    "sofia_aud": {"nombre": "Sofía Martínez", "password": hash_password("PassAud2!"), "rol": "Auditor", "departamento": "Auditoria", "estado": "Activo", "mfa_secret": pyotp.random_base32(), "permisos_extra": []}
}

RBAC_PERMISOS = {
    "Administrador": ["administrar_cuentas", "consultar_expedientes_rrhh", "crear_solicitudes", "ver_registros"],
    "RecursosHumanos": ["consultar_expedientes_rrhh"],
    "Operador": ["crear_solicitudes"],
    "Auditor": ["ver_registros"]
}

SESIONES = {}
LOGS = []

def registrar_evento(actor, tipo_evento, detalle, resultado):
    LOGS.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "actor": actor,
        "tipo_evento": tipo_evento,
        "detalle": detalle,
        "resultado": resultado
    })

def autenticar(username, password, otp_code):
    user = USUARIOS.get(username)
    if not user or user["estado"] != "Activo":
        registrar_evento(username, "LOGIN_FALLIDO", "Cuenta inexistente o suspendida", "DENEGADO")
        return None, "Acceso denegado: Cuenta inexistente o suspendida."
    
    if not verify_password(user["password"], password):
        registrar_evento(username, "LOGIN_FALLIDO", "Contraseña incorrecta", "DENEGADO")
        return None, "Credenciales inválidas."
    
    totp = pyotp.TOTP(user["mfa_secret"])
    if not totp.verify(otp_code, valid_window=1):
        registrar_evento(username, "MFA_FALLIDO", "Código TOTP inválido o vencido", "DENEGADO")
        return None, "Código MFA inválido o vencido."
    
    token = secrets.token_urlsafe(24)
    SESIONES[token] = {
        "username": username,
        "expira": datetime.now() + timedelta(minutes=30)
    }
    registrar_evento(username, "LOGIN_EXITOSO", "Autenticación y MFA completados", "PERMITIDO")
    return token, "Autenticación exitosa."

def validar_sesion(token):
    sesion = SESIONES.get(token)
    if not sesion:
        return None, "Sesión inexistente."
    if datetime.now() > sesion["expira"]:
        del SESIONES[token]
        return None, "Sesión expirada."
    user = USUARIOS.get(sesion["username"])
    if not user or user["estado"] != "Activo":
        del SESIONES[token]
        return None, "Sesión invalidada por suspensión de cuenta."
    return sesion["username"], "OK"

def verificar_rbac(user_obj, operacion):
    if operacion == "modificar_registros_auditoria":
        return False
    permisos_rol = RBAC_PERMISOS.get(user_obj["rol"], [])
    permisos_totales = set(permisos_rol + user_obj.get("permisos_extra", []))
    return operacion in permisos_totales

def evaluar_abac(user_obj, operacion, recurso_obj, entorno_obj):
    if user_obj.get("estado") != "Activo":
        return False, "DENEGADO (ABAC Política 1): Identidad no activa."
    
    if operacion == "consultar_expedientes_rrhh":
        if not recurso_obj or "departamento" not in recurso_obj:
            return False, "DENEGADO (ABAC Política 2): Falta atributo departamento en recurso."
        if user_obj.get("departamento") != recurso_obj.get("departamento"):
            return False, "DENEGADO (ABAC Política 2): Departamento no coincide."
            
    if operacion in ["administrar_cuentas", "ver_registros"]:
        if not entorno_obj or "hora" not in entorno_obj or "red" not in entorno_obj:
            return False, "DENEGADO (ABAC Política 3): Faltan atributos de entorno."
        en_horario = 8 <= entorno_obj["hora"] <= 18
        en_red_segura = entorno_obj["red"] == "corporativa"
        if not (en_horario and en_red_segura):
            return False, "DENEGADO (ABAC Política 3): Fuera de horario hábil o red no autorizada."
            
    return True, "PERMITIDO: Políticas ABAC satisfechas."

def solicitar_acceso(token, operacion, recurso_obj=None, entorno_obj=None):
    username, msg_sesion = validar_sesion(token)
    if not username:
        registrar_evento("DESCONOCIDO", "ACCESO_DENEGADO", f"{operacion} - {msg_sesion}", "DENEGADO")
        return False, msg_sesion
    
    user_obj = USUARIOS[username]
    if not verificar_rbac(user_obj, operacion):
        registrar_evento(username, "ACCESO_DENEGADO_RBAC", f"Operación: {operacion}", "DENEGADO")
        return False, f"DENEGADO (RBAC): El rol '{user_obj['rol']}' no tiene permiso para '{operacion}'."
    
    abac_ok, abac_msg = evaluar_abac(user_obj, operacion, recurso_obj, entorno_obj)
    if not abac_ok:
        registrar_evento(username, "ACCESO_DENEGADO_ABAC", f"{operacion} - {abac_msg}", "DENEGADO")
        return False, abac_msg
    
    registrar_evento(username, "ACCESO_PERMITIDO", f"Operación: {operacion}", "PERMITIDO")
    return True, f"PERMITIDO: {operacion} ejecutada por {username}."

def iam_alta_usuario(token_admin, nuevo_user, nombre, password, departamento):
    ok, msg = solicitar_acceso(token_admin, "administrar_cuentas", entorno_obj={"hora": 10, "red": "corporativa"})
    if not ok:
        return False, msg
    admin_user, _ = validar_sesion(token_admin)
    USUARIOS[nuevo_user] = {
        "nombre": nombre,
        "password": hash_password(password),
        "rol": "SinRol",
        "departamento": departamento,
        "estado": "Activo",
        "mfa_secret": pyotp.random_base32(),
        "permisos_extra": []
    }
    registrar_evento(admin_user, "IAM_ALTA", f"Usuario creado: {nuevo_user}, Depto: {departamento}", "EXITOSO")
    return True, f"Usuario {nuevo_user} creado."

def iam_cambiar_rol(token_actor, target_user, nuevo_rol):
    actor, msg_s = validar_sesion(token_actor)
    if not actor:
        return False, msg_s
    if actor == target_user:
        registrar_evento(actor, "ESCALAMIENTO_BLOQUEADO", "Intento de autoasignación de rol", "DENEGADO")
        return False, "DENEGADO: Prevención de autoasignación de privilegios."
    ok, msg = solicitar_acceso(token_actor, "administrar_cuentas", entorno_obj={"hora": 10, "red": "corporativa"})
    if not ok:
        return False, msg
    rol_anterior = USUARIOS[target_user]["rol"]
    USUARIOS[target_user]["rol"] = nuevo_rol
    registrar_evento(actor, "IAM_CAMBIO_ROL", f"Usuario: {target_user} | {rol_anterior} -> {nuevo_rol}", "EXITOSO")
    return True, f"Rol actualizado a {nuevo_rol}."

def iam_actualizar_depto(token_admin, target_user, nuevo_depto):
    ok, msg = solicitar_acceso(token_admin, "administrar_cuentas", entorno_obj={"hora": 10, "red": "corporativa"})
    if not ok:
        return False, msg
    admin_user, _ = validar_sesion(token_admin)
    anterior = USUARIOS[target_user]["departamento"]
    USUARIOS[target_user]["departamento"] = nuevo_depto
    registrar_evento(admin_user, "IAM_CAMBIO_ATRIBUTO", f"Usuario: {target_user} | Depto: {anterior} -> {nuevo_depto}", "EXITOSO")
    return True, "Departamento actualizado."

def iam_gestionar_permiso_extra(token_admin, target_user, permiso, accion):
    ok, msg = solicitar_acceso(token_admin, "administrar_cuentas", entorno_obj={"hora": 10, "red": "corporativa"})
    if not ok:
        return False, msg
    admin_user, _ = validar_sesion(token_admin)
    if accion == "conceder":
        USUARIOS[target_user]["permisos_extra"].append(permiso)
    elif accion == "revocar" and permiso in USUARIOS[target_user]["permisos_extra"]:
        USUARIOS[target_user]["permisos_extra"].remove(permiso)
    registrar_evento(admin_user, f"IAM_PERMISO_{accion.upper()}", f"Usuario: {target_user} | Permiso: {permiso}", "EXITOSO")
    return True, f"Permiso {permiso} ({accion})."

def iam_suspender_cuenta(token_admin, target_user):
    ok, msg = solicitar_acceso(token_admin, "administrar_cuentas", entorno_obj={"hora": 10, "red": "corporativa"})
    if not ok:
        return False, msg
    admin_user, _ = validar_sesion(token_admin)
    USUARIOS[target_user]["estado"] = "Suspendido"
    tokens_a_borrar = [t for t, s in SESIONES.items() if s["username"] == target_user]
    for t in tokens_a_borrar:
        del SESIONES[t]
    registrar_evento(admin_user, "IAM_SUSPENDER_CUENTA", f"Usuario: {target_user}", "EXITOSO")
    return True, f"Cuenta {target_user} suspendida y sesiones terminadas."


if __name__ == "__main__":
    print("1. PRUEBAS DE ACEPTACIÓN ACCESSGUARD \n")

    otp_carmen = pyotp.TOTP(USUARIOS["carmen_rrhh"]["mfa_secret"]).now()
    tok_carmen, msg = autenticar("carmen_rrhh", "PassRrhh1!", otp_carmen)
    print(f"[CP-01 / CP-03] Login y MFA válido (carmen_rrhh): {bool(tok_carmen)} -> {msg}")

    tok_err, msg = autenticar("carmen_rrhh", "ClaveIncorrecta", otp_carmen)
    print(f"[CP-02] Contraseña incorrecta: {bool(tok_err)} -> {msg}")

    tok_mfa_inv, msg = autenticar("carmen_rrhh", "PassRrhh1!", "000000")
    print(f"[CP-04] MFA inválido: {bool(tok_mfa_inv)} -> {msg}")

    otp_vencido = pyotp.TOTP(USUARIOS["carmen_rrhh"]["mfa_secret"]).at(time.time() - 90)
    tok_mfa_ven, msg = autenticar("carmen_rrhh", "PassRrhh1!", otp_vencido)
    print(f"[CP-05] MFA vencido: {bool(tok_mfa_ven)} -> {msg}")

    otp_bruno = pyotp.TOTP(USUARIOS["bruno_op"]["mfa_secret"]).now()
    tok_bruno, _ = autenticar("bruno_op", "PassOp1!", otp_bruno)
    res, msg = solicitar_acceso(tok_bruno, "crear_solicitudes")
    print(f"[CP-06] RBAC permiso existente (Operador -> crear_solicitudes): {res} -> {msg}")

    res, msg = solicitar_acceso(tok_bruno, "administrar_cuentas")
    print(f"[CP-07] RBAC permiso inexistente (Operador -> administrar_cuentas): {res} -> {msg}")

    res, msg = solicitar_acceso(tok_carmen, "consultar_expedientes_rrhh", recurso_obj={"departamento": "Direccion"})
    print(f"[CP-08] ABAC departamento distinto (RRHH -> Direccion): {res} -> {msg}")

    otp_ana = pyotp.TOTP(USUARIOS["ana_adm"]["mfa_secret"]).now()
    tok_ana, _ = autenticar("ana_adm", "PassAdm1!", otp_ana)
    res, msg = solicitar_acceso(tok_ana, "administrar_cuentas", entorno_obj={"hora": 11, "red": "corporativa"})
    print(f"[CP-09] ABAC atributos válidos (Admin en horario y red corp): {res} -> {msg}")

    res, msg = solicitar_acceso(tok_ana, "administrar_cuentas", entorno_obj=None)
    print(f"[CP-10] ABAC atributo obligatorio ausente: {res} -> {msg}")

    otp_elena = pyotp.TOTP(USUARIOS["elena_op"]["mfa_secret"]).now()
    tok_elena, _ = autenticar("elena_op", "PassOp2!", otp_elena)
    iam_gestionar_permiso_extra(tok_ana, "elena_op", "ver_registros", "conceder")
    iam_gestionar_permiso_extra(tok_ana, "elena_op", "ver_registros", "revocar")
    res, msg = solicitar_acceso(tok_elena, "ver_registros", entorno_obj={"hora": 11, "red": "corporativa"})
    print(f"[CP-11] Revocación de permiso: {res} -> {msg}")

    otp_david = pyotp.TOTP(USUARIOS["david_rrhh"]["mfa_secret"]).now()
    tok_david, _ = autenticar("david_rrhh", "PassRrhh2!", otp_david)
    iam_suspender_cuenta(tok_ana, "david_rrhh")
    res_sesion, msg_s = solicitar_acceso(tok_david, "consultar_expedientes_rrhh", recurso_obj={"departamento": "RRHH"})
    tok_david_nuevo, msg_l = autenticar("david_rrhh", "PassRrhh2!", pyotp.TOTP(USUARIOS["david_rrhh"]["mfa_secret"]).now())
    print(f"[CP-12] Cuenta desactivada -> Sesión previa: {res_sesion} ({msg_s}) | Nuevo login: {bool(tok_david_nuevo)} ({msg_l})")

    res_esc, msg_esc = iam_cambiar_rol(tok_bruno, "bruno_op", "Administrador")
    print(f"[CP-13] Cambio no autorizado de rol (autoescalamiento): {res_esc} -> {msg_esc}")

    secretos_expuestos = any("Pass" in str(log) or USUARIOS["ana_adm"]["mfa_secret"] in str(log) for log in LOGS)
    print(f"[CP-14] Registro de eventos: {len(LOGS)} eventos auditados | Secretos expuestos en logs: {secretos_expuestos}")

    print("\n2. DEMOSTRACIÓN COMPLETA DE CICLO IAM\n")
    print("Alta:", iam_alta_usuario(tok_ana, "nuevo_op", "Mateo Silva", "PassNuevo1!", "Operaciones"))
    print("Asignar rol:", iam_cambiar_rol(tok_ana, "nuevo_op", "Operador"))
    print("Actualizar depto:", iam_actualizar_depto(tok_ana, "nuevo_op", "Auditoria"))
    print("Suspender:", iam_suspender_cuenta(tok_ana, "nuevo_op"))



if __name__ == "__main__":
    sesion_actual = None

    while True:
        usuario_activo = "Ninguno"
        if sesion_actual:
            u_val, _ = validar_sesion(sesion_actual)
            if u_val:
                usuario_activo = f"{u_val} ({USUARIOS[u_val]['rol']} - {USUARIOS[u_val]['departamento']})"
            else:
                sesion_actual = None

        print("\n")
        print("\n")
        print("----------------------------------------------------")
        print("         ACCESSGUARD - PANEL DE DEFENSA EN VIVO     ")
        print("\n")
        print(f"Sesión activa: {usuario_activo}")
        print("1. Iniciar sesión (Usuario + Contraseña + MFA)")
        print("2. Simulador App MFA (Ver código TOTP de 6 dígitos)")
        print("3. Probar operación (Validación RBAC + ABAC)")
        print("4. Gestión IAM (Altas, Roles, Depto, Permisos, Bajas)")
        print("5. Consultar bitácora de auditoría (LOGS)")
        print("6. Cerrar sesión actual")
        print("7. Salir")
        opcion = input("Selecciona una opción: ").strip()

        if opcion == "1":
            u = input("Usuario (ej. ana_adm, carmen_rrhh, bruno_op, luis_aud): ").strip()
            p = input("Contraseña: ").strip()
            otp = input("Código TOTP (6 dígitos): ").strip()
            token, msg = autenticar(u, p, otp)
            if token:
                sesion_actual = token
            print(f"\nResultado: {msg}")

        elif opcion == "2":
            u = input("Usuario para generar token TOTP: ").strip()
            if u in USUARIOS:
                codigo = pyotp.TOTP(USUARIOS[u]["mfa_secret"]).now()
                restante = 30 - (int(datetime.now().timestamp()) % 30)
                print(f"\n[App MFA] Código vigente para {u}: {codigo} (Vence en {restante}s)")
            else:
                print("\nUsuario no encontrado.")

        elif opcion == "3":
            if not sesion_actual:
                print("\nDebes iniciar sesión primero (Opción 1).")
                continue
            print("\nOperaciones disponibles:")
            print(" - administrar_cuentas")
            print(" - consultar_expedientes_rrhh")
            print(" - crear_solicitudes")
            print(" - ver_registros")
            print(" - modificar_registros_auditoria")
            op = input("Operación a ejecutar: ").strip()

            recurso = None
            if op == "consultar_expedientes_rrhh":
                depto_rec = input("Departamento del expediente (RRHH / Direccion / TI / Operaciones): ").strip()
                recurso = {"departamento": depto_rec}

            entorno = None
            if op in ["administrar_cuentas", "ver_registros"]:
                usar_entorno = input("¿Enviar atributos de entorno? (s/n): ").strip().lower()
                if usar_entorno == "s":
                    hora = int(input("Hora de acceso (0-23): ").strip())
                    red = input("Tipo de red (corporativa / publica): ").strip()
                    entorno = {"hora": hora, "red": red}

            permitido, msg = solicitar_acceso(sesion_actual, op, recurso_obj=recurso, entorno_obj=entorno)
            print(f"\nDecisión del servidor: {msg}")

        elif opcion == "4":
            if not sesion_actual:
                print("\nDebes iniciar sesión primero (Opción 1).")
                continue
            print("\n--- Submenú IAM ---")
            print("a. Alta de usuario")
            print("b. Cambiar rol (permite probar autoescalamiento)")
            print("c. Actualizar departamento")
            print("d. Conceder o revocar permiso temporal")
            print("e. Suspender cuenta (cierra sesiones activas)")
            sub = input("Elige acción IAM: ").strip().lower()

            if sub == "a":
                nu = input("Nuevo username: ").strip()
                nom = input("Nombre completo: ").strip()
                pw = input("Contraseña: ").strip()
                dep = input("Departamento: ").strip()
                _, msg = iam_alta_usuario(sesion_actual, nu, nom, pw, dep)
                print(f"\n{msg}")

            elif sub == "b":
                tu = input("Usuario destino: ").strip()
                nr = input("Nuevo rol (Administrador / RecursosHumanos / Operador / Auditor): ").strip()
                _, msg = iam_cambiar_rol(sesion_actual, tu, nr)
                print(f"\n{msg}")

            elif sub == "c":
                tu = input("Usuario destino: ").strip()
                nd = input("Nuevo departamento: ").strip()
                _, msg = iam_actualizar_depto(sesion_actual, tu, nd)
                print(f"\n{msg}")

            elif sub == "d":
                tu = input("Usuario destino: ").strip()
                perm = input("Permiso: ").strip()
                acc = input("Acción (conceder / revocar): ").strip().lower()
                _, msg = iam_gestionar_permiso_extra(sesion_actual, tu, perm, acc)
                print(f"\n{msg}")

            elif sub == "e":
                tu = input("Usuario a suspender: ").strip()
                _, msg = iam_suspender_cuenta(sesion_actual, tu)
                print(f"\n{msg}")

        elif opcion == "5":
            print(f"\n=== BITÁCORA DE AUDITORÍA ({len(LOGS)} eventos) ===")
            for idx, ev in enumerate(LOGS, 1):
                print(f"{idx}. [{ev['timestamp']}] Actor: {ev['actor']} | {ev['tipo_evento']} | {ev['detalle']} -> {ev['resultado']}")

        elif opcion == "6":
            if sesion_actual and sesion_actual in SESIONES:
                del SESIONES[sesion_actual]
            sesion_actual = None
            print("\nSesión cerrada correctamente.")

        elif opcion == "7":
            print("\nSaliendo de AccessGuard.")
            break

        else:
            print("\nOpción no válida.")

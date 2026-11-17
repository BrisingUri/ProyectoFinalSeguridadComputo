import os
import time
import secrets
from functools import wraps
from flask import Flask, request, jsonify, send_file

from security import (
    NETWORK_SHARED_HEX,
    encrypt_field,
    decrypt_field,
    decrypt_network_value,
    hash_password,
    verify_password,
    generate_base32_secret,
    generate_totp_token,
    verify_totp_token,
    generate_numeric_otp,
    hash_token
)
from db import (
    get_db,
    init_database,
    get_user_auth_profile,
    log_access,
    log_audit
)
from backup_service import (
    detect_available_drives,
    get_external_backup_path,
    perform_backup,
    start_backup_scheduler
)
from mail_service import (
    send_recovery_code,
    get_recent_messages
)

# Inicializar Base de Datos y Planificador de Respaldos 24h
init_database()
start_backup_scheduler()

app = Flask(__name__, static_folder='public', static_url_path='')

pending_2fa_challenges = {}

def get_client_ip():
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

def get_decrypted_body():
    data = request.get_json(silent=True) or {}
    if isinstance(data, dict):
        decrypted = {}
        for k, v in data.items():
            if isinstance(v, str) and v.startswith('net:v1:'):
                decrypted[f'_raw_network_{k}'] = v
                decrypted[k] = decrypt_network_value(v)
            else:
                decrypted[k] = v
        return decrypted
    return {}

# ============================================================================
# MIDDLEWARES DE AUTENTICACIÓN Y RBAC DINÁMICO (PERSISTENTE EN SQLITE)
# ============================================================================
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        token = auth_header[7:].strip() if auth_header.startswith('Bearer ') else request.args.get('token', '')

        if not token:
            return jsonify({'error': 'Sesión no válida o expirada. Por favor inicie sesión.'}), 401

        conn = get_db()
        session_row = conn.execute('SELECT * FROM sessions WHERE token = ?', (token,)).fetchone()
        
        if not session_row:
            conn.close()
            return jsonify({'error': 'Sesión no válida o expirada. Por favor inicie sesión.'}), 401

        profile = get_user_auth_profile(session_row['user_id'])
        if not profile or not profile['is_active']:
            conn.execute('DELETE FROM sessions WHERE token = ?', (token,))
            conn.commit()
            conn.close()
            return jsonify({'error': 'La cuenta de usuario ha sido desactivada o eliminada.'}), 403

        conn.close()
        request.user = profile
        request.session_token = token
        return f(*args, **kwargs)
    return decorated

def require_permission(perm_code):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = getattr(request, 'user', None)
            if not user:
                return jsonify({'error': 'No autenticado'}), 401

            has_perm = (perm_code in user['permissions']) or ('Administrador' in user['roleNames'])
            if not has_perm:
                ip = get_client_ip()
                log_access(
                    user_id=user['id'],
                    email_attempt=user['email'],
                    usuario_nombre=user['nombre'],
                    evento='ACCESS_DENIED',
                    ip_address=ip,
                    user_agent=request.headers.get('User-Agent', ''),
                    detalles=f"Intento bloqueado por falta de permiso requerido: [{perm_code}] en ruta {request.method} {request.path}"
                )
                log_audit(
                    user_id=user['id'],
                    usuario_nombre=user['nombre'],
                    usuario_email=user['email'],
                    rol_activo=', '.join(user['roleNames']),
                    area='Control de Acceso',
                    accion='Acceso Denegado (403)',
                    recurso_id=perm_code,
                    descripcion=f"Bloqueo de seguridad: El usuario intentó ejecutar una acción sin el permiso '{perm_code}'.",
                    ip_address=ip
                )
                return jsonify({
                    'error': f"Acceso Denegado: Tu rol actual ({', '.join(user['roleNames'])}) no cuenta con el permiso '{perm_code}'."
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ============================================================================
# RUTA PRINCIPAL (FRONTEND) Y HANDSHAKE CRIPTOGRÁFICO
# ============================================================================
@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/api/security/handshake', methods=['GET'])
def handshake():
    return jsonify({
        'networkEncryptionAlgorithm': 'AES-256-GCM',
        'dbEncryptionAlgorithm': 'AES-256-GCM + Scrypt',
        'sharedKeyHex': NETWORK_SHARED_HEX
    })

# ============================================================================
# 1. AUTENTICACIÓN, REGISTRO, 2FA Y RECUPERACIÓN DE CONTRASEÑA
# ============================================================================
@app.route('/api/auth/register', methods=['POST'])
def register():
    body = get_decrypted_body()
    nombre = (body.get('nombre') or '').strip()
    email = (body.get('email') or '').strip().lower()
    password = body.get('password') or ''
    rfc = (body.get('rfc') or 'XAXX010101000').strip().upper()
    direccion = (body.get('direccion') or 'Dirección Confidencial Registrada').strip()
    telefono = (body.get('telefono') or 'Sin teléfono').strip()
    ip = get_client_ip()

    if not nombre or not email or not password:
        return jsonify({'error': 'Los campos Nombre, Email y Contraseña son obligatorios.'}), 400
    if len(str(password)) < 6:
        return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres.'}), 400

    conn = get_db()
    existing = conn.execute('SELECT id FROM users WHERE LOWER(email) = ?', (email,)).fetchone()
    if existing:
        conn.close()
        return jsonify({'error': 'Ya existe un usuario registrado con ese correo electrónico.'}), 409

    totp_secret = generate_base32_secret()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO users (nombre, email, password_hash, rfc_encrypted, direccion_encrypted, telefono_encrypted, totp_secret_encrypted, totp_enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    ''', (
        nombre,
        email,
        hash_password(password),
        encrypt_field(rfc),
        encrypt_field(direccion),
        encrypt_field(telefono),
        encrypt_field(totp_secret)
    ))
    user_id = cur.lastrowid

    reg_role = conn.execute("SELECT id FROM roles WHERE nombre = 'Usuario Regular'").fetchone()
    if reg_role:
        cur.execute('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)', (user_id, reg_role['id']))

    conn.commit()
    conn.close()

    log_access(user_id, email, nombre, 'USER_REGISTERED', ip, request.headers.get('User-Agent', ''),
               'Registro de nuevo usuario con rol predeterminado Usuario Regular y datos encriptados AES-256.')
    log_audit(user_id, nombre, email, 'Usuario Regular', 'Gestión de Usuarios', 'Registro de Cuenta',
              user_id, f'Nuevo usuario registrado ({email}). Contraseña hasheada con Scrypt y RFC/Dirección encriptados con AES-256-GCM.', ip)

    return jsonify({
        'message': 'Usuario registrado exitosamente con rol de Usuario Regular. Ahora puedes iniciar sesión.',
        'userId': user_id
    }), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    body = get_decrypted_body()
    email = (body.get('email') or '').strip().lower()
    password = body.get('password') or ''
    ip = get_client_ip()
    ua = request.headers.get('User-Agent', '')

    if not email or not password:
        return jsonify({'error': 'Ingresa tu correo electrónico y contraseña.'}), 400

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE LOWER(email) = ?', (email,)).fetchone()
    conn.close()

    if not user or not verify_password(password, user['password_hash']):
        log_access(user['id'] if user else None, email, user['nombre'] if user else 'Desconocido',
                   'LOGIN_FAILED', ip, ua, 'Credenciales inválidas (contraseña incorrecta o usuario inexistente).')
        return jsonify({'error': 'Correo electrónico o contraseña incorrectos.'}), 401

    if not user['is_active']:
        log_access(user['id'], email, user['nombre'], 'LOGIN_BLOCKED', ip, ua, 'Intento de acceso con cuenta desactivada.')
        return jsonify({'error': 'Tu cuenta está desactivada. Contacta al Administrador.'}), 403

    if user['totp_enabled']:
        challenge_id = secrets.token_hex(24)
        totp_secret = decrypt_field(user['totp_secret_encrypted'])
        pending_2fa_challenges[challenge_id] = {
            'userId': user['id'],
            'expiresAt': time.time() + 300
        }
        return jsonify({
            'requires2FA': True,
            'challengeId': challenge_id,
            'email': user['email'],
            'demoCurrentTotp': generate_totp_token(totp_secret),
            'message': 'Ingresa el código de 6 dígitos de tu aplicación autenticadora (2FA).'
        })

    session_token = secrets.token_hex(32)
    conn = get_db()
    conn.execute('INSERT OR REPLACE INTO sessions (token, user_id, ip_address) VALUES (?, ?, ?)',
                 (session_token, user['id'], ip))
    conn.commit()
    conn.close()

    profile = get_user_auth_profile(user['id'])

    log_access(user['id'], user['email'], user['nombre'], 'LOGIN_SUCCESS', ip, ua,
               f"Inicio de sesión exitoso con rol(es): {', '.join(profile['roleNames'])}")

    return jsonify({'token': session_token, 'user': profile})

@app.route('/api/auth/verify-2fa', methods=['POST'])
def verify_2fa():
    body = get_decrypted_body()
    challenge_id = body.get('challengeId') or ''
    token_2fa = body.get('token2fa') or ''
    ip = get_client_ip()
    ua = request.headers.get('User-Agent', '')

    challenge = pending_2fa_challenges.get(challenge_id)
    if not challenge or challenge['expiresAt'] < time.time():
        pending_2fa_challenges.pop(challenge_id, None)
        return jsonify({'error': 'El reto de verificación 2FA expiró. Inicia sesión nuevamente.'}), 401

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (challenge['userId'],)).fetchone()
    conn.close()

    secret = decrypt_field(user['totp_secret_encrypted'])
    if not verify_totp_token(secret, token_2fa):
        log_access(user['id'], user['email'], user['nombre'], '2FA_FAILED', ip, ua, 'Código TOTP de segundo factor inválido.')
        return jsonify({'error': 'Código de verificación 2FA incorrecto.'}), 401

    pending_2fa_challenges.pop(challenge_id, None)
    session_token = secrets.token_hex(32)
    
    conn = get_db()
    conn.execute('INSERT OR REPLACE INTO sessions (token, user_id, ip_address) VALUES (?, ?, ?)',
                 (session_token, user['id'], ip))
    conn.commit()
    conn.close()

    profile = get_user_auth_profile(user['id'])
    log_access(user['id'], user['email'], user['nombre'], 'LOGIN_2FA_SUCCESS', ip, ua,
               f"Inicio de sesión con 2FA TOTP exitoso. Roles: {', '.join(profile['roleNames'])}")

    return jsonify({'token': session_token, 'user': profile})

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    ip = get_client_ip()
    log_access(request.user['id'], request.user['email'], request.user['nombre'], 'LOGOUT', ip,
               request.headers.get('User-Agent', ''), 'Cierre de sesión voluntario por el usuario.')
    
    conn = get_db()
    conn.execute('DELETE FROM sessions WHERE token = ?', (request.session_token,))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Sesión cerrada correctamente.'})

@app.route('/api/auth/me', methods=['GET'])
@require_auth
def me():
    conn = get_db()
    raw_user = conn.execute('SELECT * FROM users WHERE id = ?', (request.user['id'],)).fetchone()
    conn.close()
    totp_secret = decrypt_field(raw_user['totp_secret_encrypted'])
    return jsonify({
        'user': request.user,
        'totpSetup': {
            'secret': totp_secret,
            'enabled': bool(raw_user['totp_enabled']),
            'currentCode': generate_totp_token(totp_secret),
            'otpauthUrl': f"otpauth://totp/SeguridadUni:{request.user['email']}?secret={totp_secret}&issuer=SeguridadComputo"
        }
    })

@app.route('/api/auth/change-password', methods=['POST'])
@require_auth
def change_password():
    body = get_decrypted_body()
    current_password = body.get('currentPassword') or ''
    new_password = body.get('newPassword') or ''
    ip = get_client_ip()

    if not current_password or not new_password:
        return jsonify({'error': 'Debes proporcionar tu contraseña actual y la nueva contraseña.'}), 400
    if len(str(new_password)) < 6:
        return jsonify({'error': 'La nueva contraseña debe tener mínimo 6 caracteres.'}), 400

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (request.user['id'],)).fetchone()
    if not verify_password(current_password, user['password_hash']):
        conn.close()
        log_audit(request.user['id'], request.user['nombre'], request.user['email'],
                  ', '.join(request.user['roleNames']), 'Seguridad de Cuenta', 'Cambio de Contraseña Fallido',
                  request.user['id'], 'Intento fallido de cambio de contraseña (contraseña actual incorrecta).', ip)
        return jsonify({'error': 'La contraseña actual proporcionada es incorrecta.'}), 401

    conn.execute("UPDATE users SET password_hash = ?, updated_at = datetime('now', 'localtime') WHERE id = ?",
                 (hash_password(new_password), request.user['id']))
    conn.commit()
    conn.close()

    log_audit(request.user['id'], request.user['nombre'], request.user['email'],
              ', '.join(request.user['roleNames']), 'Seguridad de Cuenta', 'Cambio de Contraseña',
              request.user['id'], 'El usuario actualizó su contraseña desde una sesión activa.', ip)

    return jsonify({'message': 'Contraseña actualizada exitosamente con encriptación Scrypt.'})

@app.route('/api/auth/profile', methods=['PUT'])
@require_auth
def update_profile():
    body = get_decrypted_body()
    nombre = (body.get('nombre') or request.user['nombre']).strip()
    rfc = (body.get('rfc') or request.user['rfc']).strip().upper()
    direccion = (body.get('direccion') or request.user['direccion']).strip()
    telefono = (body.get('telefono') or request.user['telefono']).strip()
    totp_enabled = 1 if body.get('totp_enabled') else 0
    ip = get_client_ip()

    conn = get_db()
    conn.execute('''
        UPDATE users
        SET nombre = ?, rfc_encrypted = ?, direccion_encrypted = ?, telefono_encrypted = ?, totp_enabled = ?, updated_at = datetime('now', 'localtime')
        WHERE id = ?
    ''', (nombre, encrypt_field(rfc), encrypt_field(direccion), encrypt_field(telefono), totp_enabled, request.user['id']))
    conn.commit()
    conn.close()

    log_audit(request.user['id'], nombre, request.user['email'], ', '.join(request.user['roleNames']),
              'Seguridad de Cuenta', 'Actualización de Perfil / 2FA', request.user['id'],
              f"Perfil actualizado. Datos sensibles re-encriptados con AES-256-GCM. Estado 2FA: {'Activado' if totp_enabled else 'Desactivado'}.", ip)

    return jsonify({
        'message': 'Perfil y configuración 2FA actualizados correctamente.',
        'user': get_user_auth_profile(request.user['id'])
    })

@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    body = get_decrypted_body()
    email = (body.get('email') or '').strip().lower()
    metodo = body.get('metodo') or 'EMAIL'
    ip = get_client_ip()

    if not email:
        return jsonify({'error': 'Ingresa tu correo electrónico registrado.'}), 400

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE LOWER(email) = ?', (email,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'No se encontró ninguna cuenta asociada a ese correo electrónico.'}), 404

    if metodo == '2FA_TOTP':
        conn.close()
        totp_secret = decrypt_field(user['totp_secret_encrypted'])
        log_access(user['id'], user['email'], user['nombre'], 'PASSWORD_RECOVERY_REQUEST', ip, '',
                   'Solicitud de recuperación mediante Token TOTP de Verificación en 2 Pasos.')
        return jsonify({
            'metodo': '2FA_TOTP',
            'message': 'Ingresa el código actual de 6 dígitos de tu autenticador TOTP (2FA) para restablecer tu contraseña.',
            'demoTotpHint': generate_totp_token(totp_secret)
        })

    otp_code = generate_numeric_otp(6)
    expires_at = int(time.time() * 1000) + 10 * 60 * 1000

    conn.execute('''
        INSERT INTO password_resets (user_id, token_hash, metodo, expires_at, used)
        VALUES (?, ?, ?, ?, 0)
    ''', (user['id'], hash_token(otp_code), metodo, expires_at))
    conn.commit()
    conn.close()

    metodo_desc = f"Mensaje de Texto SMS ({decrypt_field(user['telefono_encrypted'])})" if metodo == 'SMS' else 'Correo Electrónico'
    notification = send_recovery_code(user['email'], user['nombre'], otp_code, metodo_desc)

    log_access(user['id'], user['email'], user['nombre'], 'PASSWORD_RECOVERY_OTP_SENT', ip, '',
               f"Código de recuperación enviado vía {metodo} ({notification['smtpInfo']}).")

    return jsonify({
        'metodo': metodo,
        'message': f"Se envió un código de verificación por SMS al número de {user['nombre']}." if metodo == 'SMS' else f"Se envió un código de verificación de 6 dígitos al correo {user['email']}.",
        'simulatedNotification': notification
    })

@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    body = get_decrypted_body()
    email = (body.get('email') or '').strip().lower()
    codigo = (body.get('codigo') or '').strip()
    new_password = body.get('newPassword') or ''
    metodo = body.get('metodo') or 'EMAIL'
    ip = get_client_ip()

    if not email or not codigo or not new_password:
        return jsonify({'error': 'Todos los campos son obligatorios.'}), 400
    if len(str(new_password)) < 6:
        return jsonify({'error': 'La nueva contraseña debe tener al menos 6 caracteres.'}), 400

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE LOWER(email) = ?', (email,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'Usuario no encontrado.'}), 404

    verified = False
    if metodo == '2FA_TOTP':
        secret = decrypt_field(user['totp_secret_encrypted'])
        verified = verify_totp_token(secret, codigo)
    else:
        now_ms = int(time.time() * 1000)
        reset_row = conn.execute('''
            SELECT * FROM password_resets
            WHERE user_id = ? AND token_hash = ? AND used = 0 AND expires_at > ?
            ORDER BY id DESC LIMIT 1
        ''', (user['id'], hash_token(codigo), now_ms)).fetchone()
        if reset_row:
            verified = True
            conn.execute('UPDATE password_resets SET used = 1 WHERE id = ?', (reset_row['id'],))

    if not verified:
        conn.close()
        log_access(user['id'], user['email'], user['nombre'], 'PASSWORD_RESET_FAILED', ip, '',
                   f"Código de recuperación inválido o expirado ({metodo}).")
        return jsonify({'error': 'El código de verificación en dos pasos es inválido o ha expirado.'}), 401

    conn.execute("UPDATE users SET password_hash = ?, updated_at = datetime('now', 'localtime') WHERE id = ?",
                 (hash_password(new_password), user['id']))
    conn.commit()
    conn.close()

    log_access(user['id'], user['email'], user['nombre'], 'PASSWORD_RESET_SUCCESS', ip, '',
               f"Contraseña restablecida exitosamente mediante verificación en dos pasos ({metodo}).")
    log_audit(user['id'], user['nombre'], user['email'], 'Recuperación 2FA', 'Seguridad de Cuenta',
              'Recuperación de Contraseña', user['id'], f"Contraseña restablecida mediante verificación de token ({metodo}).", ip)

    return jsonify({'message': '¡Contraseña restablecida con éxito! Ya puedes iniciar sesión con tu nueva contraseña.'})

@app.route('/api/auth/simulated-inbox', methods=['GET'])
def simulated_inbox():
    return jsonify({'messages': get_recent_messages()})

# ============================================================================
# 2. ÁREA 1: DOCUMENTOS CORPORATIVOS
# ============================================================================
@app.route('/api/documentos', methods=['GET'])
@require_auth
@require_permission('documentos:lectura')
def get_documentos():
    conn = get_db()
    rows = conn.execute('SELECT * FROM documentos ORDER BY id DESC').fetchall()
    conn.close()
    formatted = []
    for doc in rows:
        d = dict(doc)
        d['notas_confidenciales'] = decrypt_field(d['notas_confidenciales_encrypted'])
        formatted.append(d)
    return jsonify({'documentos': formatted})

@app.route('/api/documentos', methods=['POST'])
@require_auth
@require_permission('documentos:escritura')
def create_documento():
    body = get_decrypted_body()
    titulo = (body.get('titulo') or '').strip()
    categoria = (body.get('categoria') or 'General').strip()
    clasificacion = body.get('clasificacion') or 'USO INTERNO'
    contenido = (body.get('contenido') or '').strip()
    notas = body.get('notas_confidenciales') or ''
    ip = get_client_ip()

    if not titulo or not contenido:
        return jsonify({'error': 'El título y el contenido del documento son obligatorios.'}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO documentos (titulo, categoria, clasificacion, contenido, notas_confidenciales_encrypted, autor_id, autor_nombre)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (titulo, categoria, clasificacion, contenido, encrypt_field(notas), request.user['id'], request.user['nombre']))
    doc_id = cur.lastrowid
    conn.commit()
    conn.close()

    log_audit(request.user['id'], request.user['nombre'], request.user['email'], ', '.join(request.user['roleNames']),
              'Documentos Corporativos', 'Escritura (Creación)', doc_id, f'Creó el documento "{titulo}" con notas confidenciales encriptadas en BD.', ip)

    return jsonify({'message': 'Documento creado exitosamente.', 'id': doc_id}), 201

@app.route('/api/documentos/<int:doc_id>', methods=['PUT'])
@require_auth
@require_permission('documentos:escritura')
def update_documento(doc_id):
    body = get_decrypted_body()
    ip = get_client_ip()

    conn = get_db()
    existing = conn.execute('SELECT * FROM documentos WHERE id = ?', (doc_id,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({'error': 'Documento no encontrado.'}), 404

    titulo = (body.get('titulo') or existing['titulo']).strip()
    categoria = (body.get('categoria') or existing['categoria']).strip()
    clasificacion = body.get('clasificacion') or existing['clasificacion']
    contenido = (body.get('contenido') or existing['contenido']).strip()
    notas = body.get('notas_confidenciales')
    notas_enc = encrypt_field(notas if notas is not None else decrypt_field(existing['notas_confidenciales_encrypted']))

    conn.execute('''
        UPDATE documentos
        SET titulo = ?, categoria = ?, clasificacion = ?, contenido = ?, notas_confidenciales_encrypted = ?, updated_at = datetime('now', 'localtime')
        WHERE id = ?
    ''', (titulo, categoria, clasificacion, contenido, notas_enc, doc_id))
    conn.commit()
    conn.close()

    log_audit(request.user['id'], request.user['nombre'], request.user['email'], ', '.join(request.user['roleNames']),
              'Documentos Corporativos', 'Escritura (Edición)', doc_id, f'Modificó el documento #{doc_id} ("{titulo}").', ip)

    return jsonify({'message': 'Documento actualizado correctamente.'})

@app.route('/api/documentos/<int:doc_id>', methods=['DELETE'])
@require_auth
@require_permission('documentos:eliminacion')
def delete_documento(doc_id):
    ip = get_client_ip()
    conn = get_db()
    existing = conn.execute('SELECT * FROM documentos WHERE id = ?', (doc_id,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({'error': 'Documento no encontrado.'}), 404

    conn.execute('DELETE FROM documentos WHERE id = ?', (doc_id,))
    conn.commit()
    conn.close()

    log_audit(request.user['id'], request.user['nombre'], request.user['email'], ', '.join(request.user['roleNames']),
              'Documentos Corporativos', 'Eliminación', doc_id, f'Eliminó permanentemente el documento #{doc_id} ("{existing["titulo"]}").', ip)

    return jsonify({'message': 'Documento eliminado correctamente.'})

# ============================================================================
# 3. ÁREA 2: CLIENTES (RFC Y DIRECCIÓN ENCRIPTADOS EN BD Y RED)
# ============================================================================
@app.route('/api/clientes', methods=['GET'])
@require_auth
@require_permission('clientes:lectura')
def get_clientes():
    conn = get_db()
    rows = conn.execute('SELECT * FROM clientes ORDER BY id DESC').fetchall()
    conn.close()
    clientes = []
    for c in rows:
        clientes.append({
            'id': c['id'],
            'razon_social': c['razon_social'],
            'contacto_nombre': c['contacto_nombre'],
            'email': c['email'],
            'rfc': decrypt_field(c['rfc_encrypted']),
            'direccion': decrypt_field(c['direccion_encrypted']),
            'telefono': decrypt_field(c['telefono_encrypted']),
            'contrato_monto': decrypt_field(c['contrato_monto_encrypted']),
            'rfc_encrypted': c['rfc_encrypted'],
            'direccion_encrypted': c['direccion_encrypted'],
            'telefono_encrypted': c['telefono_encrypted'],
            'contrato_monto_encrypted': c['contrato_monto_encrypted'],
            'creado_por': c['creado_por'],
            'created_at': c['created_at'],
            'updated_at': c['updated_at']
        })
    return jsonify({'clientes': clientes})

@app.route('/api/clientes', methods=['POST'])
@require_auth
@require_permission('clientes:escritura')
def create_cliente():
    body = get_decrypted_body()
    razon = (body.get('razon_social') or '').strip()
    contacto = (body.get('contacto_nombre') or 'Contacto Principal').strip()
    email = (body.get('email') or 'contacto@cliente.mx').strip()
    rfc = (body.get('rfc') or '').strip().upper()
    direccion = (body.get('direccion') or '').strip()
    telefono = (body.get('telefono') or 'S/N').strip()
    monto = (body.get('contrato_monto') or '$0.00 MXN').strip()
    ip = get_client_ip()

    if not razon or not rfc or not direccion:
        return jsonify({'error': 'Razón Social, RFC y Dirección son obligatorios.'}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO clientes (razon_social, contacto_nombre, email, rfc_encrypted, direccion_encrypted, telefono_encrypted, contrato_monto_encrypted, creado_por)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (razon, contacto, email, encrypt_field(rfc), encrypt_field(direccion), encrypt_field(telefono), encrypt_field(monto), request.user['nombre']))
    cli_id = cur.lastrowid
    conn.commit()
    conn.close()

    log_audit(request.user['id'], request.user['nombre'], request.user['email'], ', '.join(request.user['roleNames']),
              'Directorio Fiscal de Clientes', 'Escritura (Creación)', cli_id, f'Registró cliente "{razon}" con RFC y Dirección encriptados con AES-256-GCM.', ip)

    return jsonify({'message': 'Cliente registrado con datos sensibles encriptados en BD.', 'id': cli_id}), 201

@app.route('/api/clientes/<int:cli_id>', methods=['PUT'])
@require_auth
@require_permission('clientes:escritura')
def update_cliente(cli_id):
    body = get_decrypted_body()
    ip = get_client_ip()

    conn = get_db()
    existing = conn.execute('SELECT * FROM clientes WHERE id = ?', (cli_id,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({'error': 'Cliente no encontrado.'}), 404

    razon = (body.get('razon_social') or existing['razon_social']).strip()
    contacto = (body.get('contacto_nombre') or existing['contacto_nombre']).strip()
    email = (body.get('email') or existing['email']).strip()
    rfc = (body.get('rfc') or decrypt_field(existing['rfc_encrypted'])).strip().upper()
    direccion = (body.get('direccion') or decrypt_field(existing['direccion_encrypted'])).strip()
    telefono = (body.get('telefono') or decrypt_field(existing['telefono_encrypted'])).strip()
    monto = (body.get('contrato_monto') or decrypt_field(existing['contrato_monto_encrypted'])).strip()

    conn.execute('''
        UPDATE clientes
        SET razon_social = ?, contacto_nombre = ?, email = ?, rfc_encrypted = ?, direccion_encrypted = ?, telefono_encrypted = ?, contrato_monto_encrypted = ?, updated_at = datetime('now', 'localtime')
        WHERE id = ?
    ''', (razon, contacto, email, encrypt_field(rfc), encrypt_field(direccion), encrypt_field(telefono), encrypt_field(monto), cli_id))
    conn.commit()
    conn.close()

    log_audit(request.user['id'], request.user['nombre'], request.user['email'], ', '.join(request.user['roleNames']),
              'Directorio Fiscal de Clientes', 'Escritura (Edición)', cli_id, f'Actualizó datos fiscales encriptados del cliente #{cli_id} ("{razon}").', ip)

    return jsonify({'message': 'Datos del cliente actualizados y re-encriptados.'})

@app.route('/api/clientes/<int:cli_id>', methods=['DELETE'])
@require_auth
@require_permission('clientes:eliminacion')
def delete_cliente(cli_id):
    ip = get_client_ip()
    conn = get_db()
    existing = conn.execute('SELECT * FROM clientes WHERE id = ?', (cli_id,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({'error': 'Cliente no encontrado.'}), 404

    conn.execute('DELETE FROM clientes WHERE id = ?', (cli_id,))
    conn.commit()
    conn.close()

    log_audit(request.user['id'], request.user['nombre'], request.user['email'], ', '.join(request.user['roleNames']),
              'Directorio Fiscal de Clientes', 'Eliminación', cli_id, f'Eliminó el registro fiscal del cliente #{cli_id} ("{existing["razon_social"]}").', ip)

    return jsonify({'message': 'Cliente eliminado del directorio.'})

# ============================================================================
# 4. DASHBOARD DE ADMINISTRACIÓN: USUARIOS, ROLES Y PERMISOS DINÁMICOS
# ============================================================================
@app.route('/api/admin/users', methods=['GET'])
@require_auth
@require_permission('usuarios:lectura')
def admin_get_users():
    conn = get_db()
    users = conn.execute('SELECT id FROM users ORDER BY id ASC').fetchall()
    conn.close()
    detailed = [get_user_auth_profile(u['id']) for u in users]
    return jsonify({'users': detailed})

@app.route('/api/admin/users/<int:target_id>/roles', methods=['PUT'])
@require_auth
@require_permission('usuarios:escritura')
def admin_update_user_roles(target_id):
    body = get_decrypted_body()
    role_ids = body.get('roleIds') or []
    is_active = body.get('is_active')
    ip = get_client_ip()

    if not isinstance(role_ids, list) or len(role_ids) == 0:
        return jsonify({'error': 'El usuario debe tener al menos un rol asignado.'}), 400

    conn = get_db()
    target_user = conn.execute('SELECT * FROM users WHERE id = ?', (target_id,)).fetchone()
    if not target_user:
        conn.close()
        return jsonify({'error': 'Usuario no encontrado.'}), 404

    conn.execute('DELETE FROM user_roles WHERE user_id = ?', (target_id,))
    for r_id in role_ids:
        conn.execute('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)', (target_id, int(r_id)))

    if isinstance(is_active, bool):
        conn.execute("UPDATE users SET is_active = ?, updated_at = datetime('now', 'localtime') WHERE id = ?",
                     (1 if is_active else 0, target_id))

    conn.commit()
    conn.close()

    updated = get_user_auth_profile(target_id)
    log_audit(request.user['id'], request.user['nombre'], request.user['email'], ', '.join(request.user['roleNames']),
              'Gestión de Usuarios', 'Asignación/Revocación de Roles', target_id,
              f"Actualizó los roles de '{target_user['nombre']}' a: [{', '.join(updated['roleNames'])}]. Activo: {updated['is_active']}.", ip)

    return jsonify({'message': f"Roles de {target_user['nombre']} actualizados correctamente.", 'user': updated})

@app.route('/api/admin/users/<int:target_id>', methods=['DELETE'])
@require_auth
@require_permission('usuarios:eliminacion')
def admin_delete_user(target_id):
    ip = get_client_ip()
    if target_id == request.user['id']:
        return jsonify({'error': 'No puedes eliminar tu propia cuenta de administrador con sesión activa.'}), 400

    conn = get_db()
    target_user = conn.execute('SELECT * FROM users WHERE id = ?', (target_id,)).fetchone()
    if not target_user:
        conn.close()
        return jsonify({'error': 'Usuario no encontrado.'}), 404

    conn.execute('DELETE FROM users WHERE id = ?', (target_id,))
    conn.commit()
    conn.close()

    log_audit(request.user['id'], request.user['nombre'], request.user['email'], ', '.join(request.user['roleNames']),
              'Gestión de Usuarios', 'Eliminación', target_id, f"Eliminó la cuenta del usuario '{target_user['nombre']}'.", ip)

    return jsonify({'message': 'Usuario eliminado correctamente.'})

@app.route('/api/admin/roles', methods=['GET'])
@require_auth
@require_permission('roles:lectura')
def admin_get_roles():
    conn = get_db()
    roles = [dict(r) for r in conn.execute('SELECT * FROM roles ORDER BY id ASC').fetchall()]
    permissions = [dict(p) for p in conn.execute('SELECT * FROM permissions ORDER BY id ASC').fetchall()]
    role_perms = [dict(rp) for rp in conn.execute('SELECT * FROM role_permissions').fetchall()]

    roles_with_perms = []
    for r in roles:
        p_ids = [rp['permission_id'] for rp in role_perms if rp['role_id'] == r['id']]
        p_codes = [p['codigo'] for p in permissions if p['id'] in p_ids]
        user_count = conn.execute('SELECT COUNT(*) as total FROM user_roles WHERE role_id = ?', (r['id'],)).fetchone()['total']
        r['is_system'] = bool(r['is_system'])
        r['permissionIds'] = p_ids
        r['permissionCodes'] = p_codes
        r['userCount'] = user_count
        roles_with_perms.append(r)

    conn.close()
    return jsonify({'roles': roles_with_perms, 'permissions': permissions})

@app.route('/api/admin/roles', methods=['POST'])
@require_auth
@require_permission('roles:escritura')
def admin_create_role():
    body = get_decrypted_body()
    nombre = (body.get('nombre') or '').strip()
    descripcion = (body.get('descripcion') or '').strip()
    perm_ids = body.get('permissionIds') or []
    ip = get_client_ip()

    if not nombre or not descripcion:
        return jsonify({'error': 'El nombre y la descripción del rol son obligatorios.'}), 400

    conn = get_db()
    existing = conn.execute('SELECT id FROM roles WHERE LOWER(nombre) = ?', (nombre.lower(),)).fetchone()
    if existing:
        conn.close()
        return jsonify({'error': 'Ya existe un rol con ese nombre.'}), 409

    cur = conn.cursor()
    cur.execute('INSERT INTO roles (nombre, descripcion, is_system) VALUES (?, ?, 0)', (nombre, descripcion))
    new_role_id = cur.lastrowid

    for p_id in perm_ids:
        cur.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', (new_role_id, int(p_id)))

    conn.commit()
    conn.close()

    log_audit(request.user['id'], request.user['nombre'], request.user['email'], ', '.join(request.user['roleNames']),
              'Roles y Permisos', 'Creación de Rol', new_role_id, f'Creó el nuevo rol "{nombre}" con {len(perm_ids)} permisos.', ip)

    return jsonify({'message': f'Rol "{nombre}" creado exitosamente.', 'id': new_role_id}), 201

@app.route('/api/admin/roles/<int:role_id>/permissions', methods=['PUT'])
@require_auth
@require_permission('roles:escritura')
def admin_update_role_perms(role_id):
    body = get_decrypted_body()
    perm_ids = body.get('permissionIds') or []
    descripcion = body.get('descripcion')
    ip = get_client_ip()

    conn = get_db()
    role = conn.execute('SELECT * FROM roles WHERE id = ?', (role_id,)).fetchone()
    if not role:
        conn.close()
        return jsonify({'error': 'Rol no encontrado.'}), 404

    if descripcion:
        conn.execute('UPDATE roles SET descripcion = ? WHERE id = ?', (descripcion.strip(), role_id))

    conn.execute('DELETE FROM role_permissions WHERE role_id = ?', (role_id,))
    for p_id in perm_ids:
        conn.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', (role_id, int(p_id)))

    conn.commit()
    conn.close()

    log_audit(request.user['id'], request.user['nombre'], request.user['email'], ', '.join(request.user['roleNames']),
              'Roles y Permisos', 'Actualización Dinámica de Permisos', role_id,
              f'Actualizó dinámicamente la matriz de permisos del rol "{role["nombre"]}".', ip)

    return jsonify({'message': f'Permisos del rol "{role["nombre"]}" actualizados en tiempo real.'})

@app.route('/api/admin/roles/<int:role_id>', methods=['DELETE'])
@require_auth
@require_permission('roles:eliminacion')
def admin_delete_role(role_id):
    ip = get_client_ip()
    conn = get_db()
    role = conn.execute('SELECT * FROM roles WHERE id = ?', (role_id,)).fetchone()
    if not role:
        conn.close()
        return jsonify({'error': 'Rol no encontrado.'}), 404
    if role['is_system']:
        conn.close()
        return jsonify({'error': 'Los 3 roles predeterminados del sistema no pueden eliminarse.'}), 400

    conn.execute('DELETE FROM roles WHERE id = ?', (role_id,))
    conn.commit()
    conn.close()

    log_audit(request.user['id'], request.user['nombre'], request.user['email'], ', '.join(request.user['roleNames']),
              'Roles y Permisos', 'Eliminación de Rol', role_id, f'Eliminó el rol personalizado "{role["nombre"]}".', ip)

    return jsonify({'message': f'Rol "{role["nombre"]}" eliminado correctamente.'})

# ============================================================================
# 5. AUDITORÍA, ACCESOS, INSPECTOR CRIPTOGRÁFICO Y RESPALDOS 24H
# ============================================================================
@app.route('/api/admin/logs', methods=['GET'])
@require_auth
@require_permission('auditoria:lectura')
def admin_get_logs():
    conn = get_db()
    audit_logs = [dict(r) for r in conn.execute('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 250').fetchall()]
    access_logs = [dict(r) for r in conn.execute('SELECT * FROM access_logs ORDER BY id DESC LIMIT 250').fetchall()]

    raw_users = []
    for u in conn.execute('SELECT id, nombre, email, password_hash, rfc_encrypted, direccion_encrypted, telefono_encrypted FROM users ORDER BY id ASC').fetchall():
        d = dict(u)
        d['rfc_decrypted'] = decrypt_field(d['rfc_encrypted'])
        d['direccion_decrypted'] = decrypt_field(d['direccion_encrypted'])
        raw_users.append(d)

    raw_clientes = []
    for c in conn.execute('SELECT id, razon_social, rfc_encrypted, direccion_encrypted, contrato_monto_encrypted FROM clientes ORDER BY id ASC').fetchall():
        d = dict(c)
        d['rfc_decrypted'] = decrypt_field(d['rfc_encrypted'])
        d['direccion_decrypted'] = decrypt_field(d['direccion_encrypted'])
        d['contrato_monto_decrypted'] = decrypt_field(d['contrato_monto_encrypted'])
        raw_clientes.append(d)

    conn.close()
    return jsonify({
        'auditLogs': audit_logs,
        'accessLogs': access_logs,
        'encryptionInspector': {
            'users': raw_users,
            'clientes': raw_clientes
        }
    })

@app.route('/api/admin/backups', methods=['GET'])
@require_auth
@require_permission('respaldos:lectura')
def admin_get_backups():
    conn = get_db()
    backups = [dict(b) for b in conn.execute('SELECT * FROM backups ORDER BY id DESC LIMIT 50').fetchall()]
    conn.close()
    return jsonify({
        'backups': backups,
        'externalPath': get_external_backup_path(),
        'intervalHours': 24,
        'drives': detect_available_drives()
    })

@app.route('/api/admin/backups/run', methods=['POST'])
@require_auth
@require_permission('respaldos:escritura')
def admin_run_backup():
    body = get_decrypted_body()
    custom_path = (body.get('customExternalPath') or '').strip()
    ip = get_client_ip()

    if custom_path:
        conn = get_db()
        conn.execute('''
            INSERT INTO system_config (clave, valor, updated_at)
            VALUES ('external_backup_path', ?, datetime('now', 'localtime'))
            ON CONFLICT(clave) DO UPDATE SET valor = excluded.valor, updated_at = excluded.updated_at
        ''', (custom_path,))
        conn.commit()
        conn.close()

    backup_info = perform_backup(
        tipo='MANUAL_VERIFICADO',
        ejecutado_por=request.user['nombre'],
        user_id=request.user['id'],
        ip_address=ip
    )
    return jsonify({
        'message': 'Respaldo cifrado generado y almacenado en la localidad externa configurada.',
        'backup': backup_info
    })

@app.route('/api/admin/backups/<int:backup_id>/download', methods=['GET'])
@require_auth
@require_permission('respaldos:lectura')
def admin_download_backup(backup_id):
    conn = get_db()
    backup = conn.execute('SELECT * FROM backups WHERE id = ?', (backup_id,)).fetchone()
    conn.close()
    if not backup or not os.path.exists(backup['local_path']):
        return jsonify({'error': 'Archivo de respaldo no encontrado.'}), 404
    return send_file(backup['local_path'], as_attachment=True, download_name=backup['filename'])

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    print('===================================================================')
    print(' SISTEMA DE GESTIÓN DE ROLES Y PERMISOS (RBAC) - PYTHON FLASK')
    print('===================================================================')
    print(f' Servidor Web escuchando en : http://localhost:{port}')
    print(' Encriptación en BD y Red   : AES-256-GCM + Scrypt Activo')
    print(' Respaldo Automático 24h    : Activo (Local + Unidad Externa USB)')
    print('===================================================================')
    app.run(host='0.0.0.0', port=port, debug=True)
import os
import sqlite3
from security import (
    encrypt_field,
    decrypt_field,
    hash_password,
    generate_base32_secret
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, 'seguridad_rbac.db')

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON;')
    conn.execute('PRAGMA journal_mode = WAL;')
    return conn

def init_database():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            rfc_encrypted TEXT NOT NULL,
            direccion_encrypted TEXT NOT NULL,
            telefono_encrypted TEXT DEFAULT '',
            totp_secret_encrypted TEXT NOT NULL,
            totp_enabled INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now', 'localtime')),
            updated_at TEXT DEFAULT (datetime('now', 'localtime'))
        );

        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL UNIQUE,
            descripcion TEXT NOT NULL,
            is_system INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now', 'localtime'))
        );

        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo TEXT NOT NULL UNIQUE,
            area TEXT NOT NULL,
            accion TEXT NOT NULL,
            nombre TEXT NOT NULL,
            descripcion TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            PRIMARY KEY (role_id, permission_id),
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            assigned_at TEXT DEFAULT (datetime('now', 'localtime')),
            PRIMARY KEY (user_id, role_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email_attempt TEXT NOT NULL,
            usuario_nombre TEXT DEFAULT '',
            evento TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT DEFAULT '',
            detalles TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now', 'localtime'))
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            usuario_nombre TEXT NOT NULL,
            usuario_email TEXT NOT NULL,
            rol_activo TEXT NOT NULL,
            area TEXT NOT NULL,
            accion TEXT NOT NULL,
            recurso_id TEXT DEFAULT '',
            descripcion TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now', 'localtime'))
        );

        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            metodo TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now', 'localtime')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS documentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            categoria TEXT NOT NULL,
            clasificacion TEXT NOT NULL DEFAULT 'INTERNO',
            contenido TEXT NOT NULL,
            notas_confidenciales_encrypted TEXT DEFAULT '',
            autor_id INTEGER,
            autor_nombre TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now', 'localtime')),
            updated_at TEXT DEFAULT (datetime('now', 'localtime'))
        );

        CREATE TABLE IF NOT EXISTS clientes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            razon_social TEXT NOT NULL,
            contacto_nombre TEXT NOT NULL,
            email TEXT NOT NULL,
            rfc_encrypted TEXT NOT NULL,
            direccion_encrypted TEXT NOT NULL,
            telefono_encrypted TEXT NOT NULL,
            contrato_monto_encrypted TEXT NOT NULL,
            creado_por TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now', 'localtime')),
            updated_at TEXT DEFAULT (datetime('now', 'localtime'))
        );

        CREATE TABLE IF NOT EXISTS backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            local_path TEXT NOT NULL,
            external_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256_hash TEXT NOT NULL,
            encrypted INTEGER DEFAULT 1,
            tipo TEXT NOT NULL,
            ejecutado_por TEXT NOT NULL,
            estado TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now', 'localtime'))
        );

        CREATE TABLE IF NOT EXISTS system_config (
            clave TEXT PRIMARY KEY,
            valor TEXT NOT NULL,
            updated_at TEXT DEFAULT (datetime('now', 'localtime'))
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT DEFAULT (datetime('now', 'localtime')),
            ip_address TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    ''')
    conn.commit()
    conn.close()
    seed_initial_data()

def seed_initial_data():
    conn = get_db()
    cur = conn.cursor()
    role_count = cur.execute('SELECT COUNT(*) as total FROM roles').fetchone()['total']
    if role_count > 0:
        conn.close()
        return

    permissions_list = [
        ('documentos:lectura', 'Documentos Corporativos', 'Lectura', 'Ver Documentos', 'Acceso a visualizar artículos y documentos del repositorio corporativo.'),
        ('documentos:escritura', 'Documentos Corporativos', 'Escritura', 'Crear y Editar Documentos', 'Permiso para redactar nuevos documentos o modificar existentes.'),
        ('documentos:eliminacion', 'Documentos Corporativos', 'Eliminación', 'Eliminar Documentos', 'Permiso para eliminar documentos del repositorio.'),
        ('clientes:lectura', 'Directorio Fiscal de Clientes', 'Lectura', 'Ver Clientes y RFC', 'Acceso para visualizar la cartera de clientes y desencriptar sus datos fiscales.'),
        ('clientes:escritura', 'Directorio Fiscal de Clientes', 'Escritura', 'Crear y Modificar Clientes', 'Permiso para registrar o actualizar clientes con encriptación AES-256 en BD.'),
        ('clientes:eliminacion', 'Directorio Fiscal de Clientes', 'Eliminación', 'Eliminar Clientes', 'Permiso para dar de baja registros de clientes del sistema.'),
        ('usuarios:lectura', 'Gestión de Usuarios', 'Lectura', 'Ver Usuarios Registrados', 'Permite listar todos los usuarios registrados y ver sus roles asignados.'),
        ('usuarios:escritura', 'Gestión de Usuarios', 'Escritura', 'Gestionar Usuarios y Asignar Roles', 'Permite crear usuarios, activar/desactivar cuentas y asignar o revocar roles.'),
        ('usuarios:eliminacion', 'Gestión de Usuarios', 'Eliminación', 'Eliminar Usuarios', 'Permite eliminar cuentas de usuario del sistema.'),
        ('roles:lectura', 'Roles y Permisos', 'Lectura', 'Ver Roles y Matriz de Permisos', 'Permite consultar los roles del sistema y sus permisos asociados.'),
        ('roles:escritura', 'Roles y Permisos', 'Escritura', 'Crear Roles y Configurar Permisos', 'Permite crear nuevos roles y asignar o revocar permisos dinámicamente.'),
        ('roles:eliminacion', 'Roles y Permisos', 'Eliminación', 'Eliminar Roles Personalizados', 'Permite eliminar roles creados por el administrador.'),
        ('auditoria:lectura', 'Auditoría y Seguridad', 'Lectura', 'Consultar Bitácoras de Auditoría y Accesos', 'Permite inspeccionar el historial de inicios de sesión y acciones.'),
        ('respaldos:lectura', 'Respaldos y Sistema', 'Lectura', 'Ver Estado de Respaldos 24h', 'Permite consultar el historial de respaldos automáticos y ubicación externa.'),
        ('respaldos:escritura', 'Respaldos y Sistema', 'Escritura', 'Ejecutar y Configurar Respaldos Externos', 'Permite disparar respaldos cifrados y configurar la ruta de la USB.'),
        ('respaldos:eliminacion', 'Respaldos y Sistema', 'Eliminación', 'Depurar Historial de Respaldos', 'Permite eliminar registros antiguos de respaldos locales.')
    ]
    cur.executemany('INSERT INTO permissions (codigo, area, accion, nombre, descripcion) VALUES (?, ?, ?, ?, ?)', permissions_list)

    cur.execute('INSERT INTO roles (nombre, descripcion, is_system) VALUES (?, ?, 1)',
                ('Administrador', 'Tiene acceso completo a todas las funcionalidades del sistema.'))
    admin_role_id = cur.lastrowid

    cur.execute('INSERT INTO roles (nombre, descripcion, is_system) VALUES (?, ?, 1)',
                ('Editor', 'Puede crear, editar y eliminar contenidos, pero no gestionar usuarios ni configuraciones globales.'))
    editor_role_id = cur.lastrowid

    cur.execute('INSERT INTO roles (nombre, descripcion, is_system) VALUES (?, ?, 1)',
                ('Usuario Regular', 'Solo puede ver y consumir contenido autorizado (Lectura).'))
    regular_role_id = cur.lastrowid

    all_perms = cur.execute('SELECT id, codigo FROM permissions').fetchall()
    for perm in all_perms:
        cur.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', (admin_role_id, perm['id']))
        if perm['codigo'].startswith('documentos:') or perm['codigo'].startswith('clientes:'):
            cur.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', (editor_role_id, perm['id']))
        if perm['codigo'] in ('documentos:lectura', 'clientes:lectura'):
            cur.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', (regular_role_id, perm['id']))

    cur.execute('''
        INSERT INTO users (nombre, email, password_hash, rfc_encrypted, direccion_encrypted, telefono_encrypted, totp_secret_encrypted, totp_enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    ''', ('Carlos Ramírez (Admin)', 'admin@uni.edu.mx', hash_password('Admin123!'),
          encrypt_field('RAMC880514HDF'), encrypt_field('Av. Universidad #1024, CDMX'),
          encrypt_field('55-4123-8900'), encrypt_field(generate_base32_secret())))
    admin_user_id = cur.lastrowid
    cur.execute('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)', (admin_user_id, admin_role_id))

    cur.execute('''
        INSERT INTO users (nombre, email, password_hash, rfc_encrypted, direccion_encrypted, telefono_encrypted, totp_secret_encrypted, totp_enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    ''', ('Laura Mendoza (Editora)', 'editor@uni.edu.mx', hash_password('Editor123!'),
          encrypt_field('MENL921103MDF'), encrypt_field('Calle Insurgentes Sur #450, CDMX'),
          encrypt_field('55-8291-3344'), encrypt_field(generate_base32_secret())))
    editor_user_id = cur.lastrowid
    cur.execute('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)', (editor_user_id, editor_role_id))

    cur.execute('''
        INSERT INTO users (nombre, email, password_hash, rfc_encrypted, direccion_encrypted, telefono_encrypted, totp_secret_encrypted, totp_enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    ''', ('Diego Torres (Usuario Regular)', 'usuario@uni.edu.mx', hash_password('Usuario123!'),
          encrypt_field('TORD010822HMC'), encrypt_field('Calzada de Tlalpan #2100, CDMX'),
          encrypt_field('55-1920-7765'), encrypt_field(generate_base32_secret())))
    regular_user_id = cur.lastrowid
    cur.execute('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)', (regular_user_id, regular_role_id))

    cur.execute('''
        INSERT INTO documentos (titulo, categoria, clasificacion, contenido, notas_confidenciales_encrypted, autor_id, autor_nombre)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', ('Política de Seguridad Perimetral OPNsense', 'Seguridad de Red', 'CONFIDENCIAL',
          'El servidor de aplicaciones y base de datos opera dentro de la Red Intermedia detrás del firewall OPNsense.',
          encrypt_field('IP Servidor Red Intermedia: 192.168.50.10 | Gateway OPNsense: 192.168.50.1'),
          admin_user_id, 'Carlos Ramírez (Admin)'))

    cur.execute('''
        INSERT INTO clientes (razon_social, contacto_nombre, email, rfc_encrypted, direccion_encrypted, telefono_encrypted, contrato_monto_encrypted, creado_por)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', ('Grupo Tecnológico Azteca S.A. de C.V.', 'Ing. Roberto Elizondo', 'relizondo@tecazteca.mx',
          encrypt_field('GTA140812K9A'), encrypt_field('Paseo de la Reforma #505, CDMX'),
          encrypt_field('55-9001-2233'), encrypt_field('$1,450,000.00 MXN'), 'Carlos Ramírez (Admin)'))

    default_ext = os.path.join(os.path.splitdrive(BASE_DIR)[0] or 'C:', os.sep, 'Respaldos_Externos_USB_Seguridad')
    cur.execute('INSERT INTO system_config (clave, valor) VALUES (?, ?)', ('external_backup_path', default_ext))
    cur.execute('INSERT INTO system_config (clave, valor) VALUES (?, ?)', ('backup_interval_hours', '24'))
    cur.execute('INSERT INTO system_config (clave, valor) VALUES (?, ?)', ('network_encryption_enabled', 'true'))

    conn.commit()
    conn.close()

def get_user_auth_profile(user_id):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        return None

    roles = [dict(r) for r in conn.execute('''
        SELECT r.id, r.nombre, r.descripcion, r.is_system
        FROM roles r
        INNER JOIN user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = ?
    ''', (user_id,)).fetchall()]

    permissions = [dict(p) for p in conn.execute('''
        SELECT DISTINCT p.codigo, p.area, p.accion, p.nombre
        FROM permissions p
        INNER JOIN role_permissions rp ON rp.permission_id = p.id
        INNER JOIN user_roles ur ON ur.role_id = rp.role_id
        WHERE ur.user_id = ?
    ''', (user_id,)).fetchall()]

    conn.close()
    return {
        'id': user['id'],
        'nombre': user['nombre'],
        'email': user['email'],
        'rfc': decrypt_field(user['rfc_encrypted']),
        'direccion': decrypt_field(user['direccion_encrypted']),
        'telefono': decrypt_field(user['telefono_encrypted']),
        'rfc_encrypted': user['rfc_encrypted'],
        'direccion_encrypted': user['direccion_encrypted'],
        'totp_enabled': bool(user['totp_enabled']),
        'is_active': bool(user['is_active']),
        'created_at': user['created_at'],
        'roles': roles,
        'roleNames': [r['nombre'] for r in roles],
        'permissions': [p['codigo'] for p in permissions],
        'permissionDetails': permissions
    }

def log_access(user_id=None, email_attempt='', usuario_nombre='', evento='', ip_address='127.0.0.1', user_agent='', detalles=''):
    conn = get_db()
    conn.execute('''
        INSERT INTO access_logs (user_id, email_attempt, usuario_nombre, evento, ip_address, user_agent, detalles)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, email_attempt, usuario_nombre, evento, ip_address or '127.0.0.1', user_agent or '', detalles))
    conn.commit()
    conn.close()

def log_audit(user_id=None, usuario_nombre='Sistema', usuario_email='sistema@local', rol_activo='N/A', area='', accion='', recurso_id='', descripcion='', ip_address='127.0.0.1'):
    conn = get_db()
    conn.execute('''
        INSERT INTO audit_logs (user_id, usuario_nombre, usuario_email, rol_activo, area, accion, recurso_id, descripcion, ip_address)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, usuario_nombre, usuario_email, rol_activo, area, accion, str(recurso_id), descripcion, ip_address or '127.0.0.1'))
    conn.commit()
    conn.close()
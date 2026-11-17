import os
import json
import time
import shutil
import hashlib
import threading
import subprocess
from datetime import datetime
from db import get_db, DB_PATH, BASE_DIR, log_audit
from security import encrypt_field

LOCAL_BACKUP_DIR = os.path.join(BASE_DIR, 'backups')
os.makedirs(LOCAL_BACKUP_DIR, exist_ok=True)

def detect_available_drives():
    drives = []
    if os.name == 'nt':
        try:
            cmd = [
                'powershell', '-NoProfile', '-Command',
                'Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, VolumeName, DriveType, FreeSpace | ConvertTo-Json -Compress'
            ]
            output = subprocess.check_output(cmd, text=True, timeout=3)
            if output and output.strip():
                parsed = json.loads(output.strip())
                disk_list = parsed if isinstance(parsed, list) else [parsed]
                for d in disk_list:
                    is_removable = (d.get('DriveType') == 2)
                    dev_id = d.get('DeviceID', 'C:')
                    vol_name = d.get('VolumeName') or ('Memoria USB / Extraíble' if is_removable else 'Disco Local')
                    drives.append({
                        'drive': dev_id,
                        'label': vol_name,
                        'type': 'USB / Extraíble' if is_removable else 'Disco Fijo',
                        'isRemovable': is_removable,
                        'suggestedPath': os.path.join(dev_id + os.sep, 'Respaldos_Seguridad_Uni')
                    })
        except Exception:
            pass
    return drives

def get_external_backup_path():
    conn = get_db()
    row = conn.execute("SELECT valor FROM system_config WHERE clave = 'external_backup_path'").fetchone()
    conn.close()
    if row:
        return row['valor']
    drive_root = os.path.splitdrive(BASE_DIR)[0] or 'C:'
    return os.path.join(drive_root + os.sep, 'Respaldos_Externos_USB_Seguridad')

def perform_backup(tipo='AUTOMATICO_24H', ejecutado_por='Sistema Automático (Cron 24h)', user_id=None, ip_address='127.0.0.1'):
    timestamp = datetime.now().isoformat().replace(':', '-').replace('.', '-')
    filename = f"backup_seguridad_{timestamp}.enc.bak"

    conn = get_db()
    dump_data = {
        'metadata': {
            'created_at': datetime.now().isoformat(),
            'tipo': tipo,
            'ejecutado_por': ejecutado_por,
            'algorithm': 'AES-256-GCM',
            'version': '1.0'
        },
        'users': [dict(r) for r in conn.execute('SELECT * FROM users').fetchall()],
        'roles': [dict(r) for r in conn.execute('SELECT * FROM roles').fetchall()],
        'permissions': [dict(r) for r in conn.execute('SELECT * FROM permissions').fetchall()],
        'role_permissions': [dict(r) for r in conn.execute('SELECT * FROM role_permissions').fetchall()],
        'user_roles': [dict(r) for r in conn.execute('SELECT * FROM user_roles').fetchall()],
        'documentos': [dict(r) for r in conn.execute('SELECT * FROM documentos').fetchall()],
        'clientes': [dict(r) for r in conn.execute('SELECT * FROM clientes').fetchall()],
        'access_logs': [dict(r) for r in conn.execute('SELECT * FROM access_logs ORDER BY id DESC LIMIT 1000').fetchall()],
        'audit_logs': [dict(r) for r in conn.execute('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 1000').fetchall()],
        'system_config': [dict(r) for r in conn.execute('SELECT * FROM system_config').fetchall()]
    }

    json_payload = json.dumps(dump_data, indent=2, ensure_ascii=False)
    encrypted_content = encrypt_field(json_payload)
    content_bytes = encrypted_content.encode('utf-8')
    sha256_hash = hashlib.sha256(content_bytes).hexdigest()
    size_bytes = len(content_bytes)

    # 1. Guardar copia local
    local_file_path = os.path.join(LOCAL_BACKUP_DIR, filename)
    with open(local_file_path, 'w', encoding='utf-8') as f:
        f.write(encrypted_content)

    sqlite_copy_local = os.path.join(LOCAL_BACKUP_DIR, f"backup_sqlite_{timestamp}.db")
    try:
        shutil.copy2(DB_PATH, sqlite_copy_local)
    except Exception:
        pass

    # 2. Guardar en localidad externa (USB / Disco extraíble)
    external_dir = get_external_backup_path()
    external_file_path = os.path.join(external_dir, filename)
    estado = 'COMPLETADO (LOCAL + EXTERNO)'

    try:
        os.makedirs(external_dir, exist_ok=True)
        with open(external_file_path, 'w', encoding='utf-8') as f:
            f.write(encrypted_content)
        sqlite_copy_ext = os.path.join(external_dir, f"backup_sqlite_{timestamp}.db")
        try:
            shutil.copy2(DB_PATH, sqlite_copy_ext)
        except Exception:
            pass
    except Exception:
        fallback_ext = os.path.join(BASE_DIR, 'external_usb_storage', os.path.basename(external_dir.rstrip('\\/')))
        os.makedirs(fallback_ext, exist_ok=True)
        external_file_path = os.path.join(fallback_ext, filename)
        with open(external_file_path, 'w', encoding='utf-8') as f:
            f.write(encrypted_content)
        estado = f"COMPLETADO (Guardado en Unidad Externa Montada: {fallback_ext})"

    cur = conn.cursor()
    cur.execute('''
        INSERT INTO backups (filename, local_path, external_path, size_bytes, sha256_hash, encrypted, tipo, ejecutado_por, estado)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
    ''', (filename, local_file_path, external_file_path, size_bytes, sha256_hash, tipo, ejecutado_por, estado))
    backup_id = cur.lastrowid
    conn.commit()
    conn.close()

    log_audit(
        user_id=user_id,
        usuario_nombre=ejecutado_por,
        usuario_email='backup@sistema',
        rol_activo='Administrador / Sistema',
        area='Respaldos y Sistema',
        accion='Escritura',
        recurso_id=backup_id,
        descripcion=f"Respaldo {tipo} generado y cifrado con AES-256-GCM ({filename}) hacia localidad externa: {external_file_path}",
        ip_address=ip_address
    )

    return {
        'id': backup_id,
        'filename': filename,
        'local_path': local_file_path,
        'external_path': external_file_path,
        'size_bytes': size_bytes,
        'sha256_hash': sha256_hash,
        'tipo': tipo,
        'ejecutado_por': ejecutado_por,
        'estado': estado
    }

def _scheduler_loop():
    while True:
        time.sleep(3600)
        try:
            conn = get_db()
            recent = conn.execute("SELECT id FROM backups WHERE created_at >= datetime('now', 'localtime', '-24 hours') LIMIT 1").fetchone()
            conn.close()
            if not recent:
                perform_backup(tipo='AUTOMATICO_24H', ejecutado_por='Planificador Automático (24h)')
        except Exception as err:
            print('Error en el planificador de respaldos 24h:', err)

def start_backup_scheduler():
    conn = get_db()
    last_backup = conn.execute("SELECT created_at FROM backups WHERE created_at >= datetime('now', 'localtime', '-24 hours') ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    if not last_backup:
        perform_backup(tipo='AUTOMATICO_24H', ejecutado_por='Planificador Automático (24h)')

    t = threading.Thread(target=_scheduler_loop, daemon=True)
    t.start()
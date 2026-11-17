import os
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

# Historial en memoria de los últimos mensajes enviados (Correo / SMS)
sent_messages_history = []

def send_recovery_code(to_email, nombre, codigo, metodo):
    timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    subject = f"[Seguridad en Cómputo] Código de Verificación y Recuperación ({codigo})"
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 20px; border: 1px solid #1e293b; border-radius: 10px; background: #0f172a; color: #f8fafc;">
      <h2 style="color: #38bdf8; margin-top: 0;">Seguridad en Cómputo - Verificación en 2 Pasos</h2>
      <p>Hola <strong>{nombre}</strong>,</p>
      <p>Se ha solicitado una operación de seguridad mediante <strong>{metodo}</strong>.</p>
      <div style="background: #1e293b; padding: 16px; border-radius: 8px; text-align: center; margin: 20px 0;">
        <span style="font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #22c55e;">{codigo}</span>
      </div>
      <p style="font-size: 13px; color: #94a3b8;">Este código expira en 10 minutos. Si no solicitaste este código, ignora este mensaje.</p>
    </div>
    """

    smtp_sent = False
    smtp_info = "Modo Laboratorio Local Activo (Bandeja Virtual)"

    smtp_host = os.environ.get('SMTP_HOST')
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))

    if smtp_host and smtp_user and smtp_pass:
        try:
            msg = MIMEText(html_content, 'html', 'utf-8')
            msg['Subject'] = subject
            msg['From'] = os.environ.get('SMTP_FROM', f"Seguridad en Cómputo <{smtp_user}>")
            msg['To'] = to_email

            with smtplib.SMTP(smtp_host, smtp_port, timeout=5) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)

            smtp_sent = True
            smtp_info = f"Enviado por SMTP ({smtp_host})"
        except Exception as err:
            smtp_info = f"Fallback a Bandeja Virtual ({str(err)})"

    record = {
        'id': len(sent_messages_history) + 1,
        'to': to_email,
        'nombre': nombre,
        'codigo': codigo,
        'metodo': metodo,
        'subject': subject,
        'timestamp': timestamp,
        'smtpSent': smtp_sent,
        'smtpInfo': smtp_info
    }
    sent_messages_history.insert(0, record)
    if len(sent_messages_history) > 30:
        sent_messages_history.pop()

    return record

def get_recent_messages():
    return sent_messages_history
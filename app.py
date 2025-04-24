from flask import Flask, request, jsonify
import requests
import os
import logging
from datetime import datetime
import hmac
import hashlib
import base64

app = Flask(__name__)

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# Configuración específica
GOOGLE_CHAT_WEBHOOK_URL = "https://chat.googleapis.com/v1/spaces/AAQA0RGKcXM/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=vtK7l458_AvwTQjctG-WGprheihrzEhm3je68Hjb77Q"
WEBHOOK_SECRET_TOKEN = "pUxoz2wNR0uiHOOqegBUfQ"  # Tu nuevo token
MEETING_IDS = [
    "93858743199",
    "91678387079",
    "96740019814",
    "96399981276",
    "98502601831",
    "96915642741",
    "95692627898",
    "96023758677"
]

def verify_zoom_webhook(request_body, request_headers):
    """Verifica la firma del webhook de Zoom"""
    try:
        timestamp = request_headers.get('X-Zm-Request-Timestamp', '')
        signature = request_headers.get('X-Zm-Signature', '')

        if not timestamp or not signature:
            return False

        message = f"v0:{timestamp}:{request_body}"
        hash_object = hmac.new(
            WEBHOOK_SECRET_TOKEN.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        )
        expected_signature = f"v0={hash_object.hexdigest()}"

        return signature == expected_signature
    except Exception as e:
        app.logger.error(f"Error verificando webhook: {str(e)}")
        return False

def send_to_google_chat(message):
    """Envía mensaje a Google Chat con manejo de errores"""
    try:
        app.logger.info(f"Enviando mensaje a Google Chat: {message}")
        response = requests.post(
            GOOGLE_CHAT_WEBHOOK_URL,
            json={"text": message},
            verify=True
        )
        response.raise_for_status()
        app.logger.info(f"Mensaje enviado exitosamente: {message}")
        return True
    except Exception as e:
        app.logger.error(f"Error enviando mensaje a Google Chat: {str(e)}")
        return False

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.get_json(silent=True)
    # Si es validación de URL, responde sin verificar la firma
    if data and data.get('event') == 'endpoint.url_validation':
        plain_token = data.get('payload', {}).get('plainToken')
        if plain_token:
            import hmac, hashlib, base64
            secret = "pUxoz2wNR0uiHOOqegBUfQ"
            hash_object = hmac.new(
                secret.encode('utf-8'),
                plain_token.encode('utf-8'),
                hashlib.sha256
            )
            encrypted_token = base64.b64encode(hash_object.digest()).decode('utf-8')
            return jsonify({
                "plainToken": plain_token,
                "encryptedToken": encrypted_token
            }), 200
    # Para otros eventos, aquí sí puedes verificar la firma si lo deseas
    return jsonify({"status": "ok"}), 200

        # ... resto del código para procesar eventos normales ...

    except Exception as e:
        app.logger.error(f"Error procesando webhook: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.logger.info(f"Iniciando servidor en puerto {port}")
    app.run(host='0.0.0.0', port=port)

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
WEBHOOK_SECRET_TOKEN = "aEoem48nQ_ex8iE49Yvvnw"
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

@app.route('/')
def root():
    return jsonify({
        'status': 'running',
        'message': 'Zoom Webhook Service is running',
        'endpoints': ['/webhook']
    }), 200

@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    """Endpoint principal para webhooks de Zoom"""
    app.logger.info(f"Request from IP: {request.remote_addr}")
    app.logger.info(f"Método recibido: {request.method}")
    app.logger.info(f"Headers recibidos: {dict(request.headers)}")

    if request.method == 'GET':
        return jsonify({
            'status': 'ready',
            'message': 'Zoom Webhook endpoint is ready for POST requests'
        }), 200

    try:
        data = request.get_json(silent=True)
        app.logger.info(f"Body recibido: {data}")

        # Validación inicial de Zoom (endpoint.url_validation)
        if data and data.get('event') == 'endpoint.url_validation':
            plain_token = data.get('payload', {}).get('plainToken')
            if plain_token:
                app.logger.info(f"Recibido plainToken para validación: {plain_token}")
                hash_object = hmac.new(
                    WEBHOOK_SECRET_TOKEN.encode('utf-8'),
                    plain_token.encode('utf-8'),
                    hashlib.sha256
                )
                encrypted_token = base64.b64encode(hash_object.digest()).decode('utf-8')
                response = {
                    "plainToken": plain_token,
                    "encryptedToken": encrypted_token
                }
                app.logger.info(f"Respondiendo a validación de Zoom: {response}")
                return jsonify(response), 200

        # Procesamiento de eventos normales
        event = data.get('event') if data else None
        if not event:
            app.logger.info("Petición sin evento - posible prueba")
            return jsonify({'status': 'ok', 'message': 'no event but accepted'}), 200

        # Extraer información del evento
        payload = data.get('payload', {}).get('object', {})
        meeting_id = str(payload.get('id', ''))
        topic = payload.get('topic', 'Sin título')
        host_email = payload.get('host_email', 'No disponible')

        # Verificar si la reunión está en la lista de monitoreo
        if meeting_id and meeting_id not in MEETING_IDS:
            app.logger.info(f"Reunión {meeting_id} no está en la lista de monitoreo")
            return jsonify({
                'status': 'ignored',
                'reason': 'meeting_id not monitored',
                'meeting_id': meeting_id
            }), 200

        # Definir mensajes para diferentes eventos
        messages = {
            'meeting.started': (
                f'🟢 Reunión iniciada\n'
                f'📅 Título: "{topic}"\n'
                f'🆔 ID: {meeting_id}\n'
                f'👤 Host: {host_email}'
            ),
            'meeting.live_streaming_started': (
                f'🔴 Transmisión en vivo iniciada\n'
                f'📅 Título: "{topic}"\n'
                f'🆔 ID: {meeting_id}\n'
                f'👤 Host: {host_email}'
            ),
            'meeting.ended': (
                f'⭕ Reunión finalizada\n'
                f'📅 Título: "{topic}"\n'
                f'🆔 ID: {meeting_id}\n'
                f'👤 Host: {host_email}'
            )
        }

        # Procesar evento si está en la lista de mensajes
        if event in messages:
            message = messages[event]
            app.logger.info(f"Procesando evento {event} para reunión {meeting_id}")

            if send_to_google_chat(message):
                return jsonify({
                    'status': 'success',
                    'message': 'notification sent',
                    'event': event,
                    'meeting_id': meeting_id
                }), 200
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'failed to send notification',
                    'event': event,
                    'meeting_id': meeting_id
                }), 200

        # Evento no monitoreado
        app.logger.info(f"Evento no monitoreado: {event}")
        return jsonify({
            'status': 'ignored',
            'reason': 'event not monitored',
            'event': event
        }), 200

    except Exception as e:
        app.logger.error(f"Error procesando webhook: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.logger.info(f"Iniciando servidor en puerto {port}")
    app.run(host='0.0.0.0', port=port)

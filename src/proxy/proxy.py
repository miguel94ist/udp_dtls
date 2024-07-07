# To run Proxy Application you need the following files:
#  -> "cert/listeners_proxy.cfg" - configuration file that holds listeners configuration by ApparatusID
#  -> "cert/server.key"          - server certificate private key
#  -> "cert/server.pem"          - server certificate public part, that is expected in Proxy Application
#  -> "cert/ca.pem"              - ca certificate public part

import socket
import ssl
import logging
import base64
import configparser
from dtls import do_patch
from dtls.sslconnection import SSLConnection, PROTOCOL_DTLSv1_2
from OpenSSL import crypto
import threading
from flask import Flask, request, jsonify

do_patch()

# Configuration
LISTEN_IP = '0.0.0.0'
FORWARD_IP = '127.0.0.1'

# Flask app
app = Flask(__name__)

# Set up logging
#logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def extract_public_key(cert_pem):
    try:
        cert_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        public_key = cert_obj.get_pubkey()
        pub_key_str = crypto.dump_publickey(crypto.FILETYPE_PEM, public_key)
        logging.debug(f"Extracted public key: {pub_key_str}")
        return pub_key_str
    except Exception as e:
        logging.error(f"Error extracting public key: {e}")
        return None

def verify_certificate(client_cert_pem, expected_cert_pem):
    try:
        expected_pub_key = extract_public_key(expected_cert_pem)
        logging.debug(f"Expected public key: {expected_pub_key}")
        actual_pub_key = extract_public_key(client_cert_pem)
        logging.debug(f"Actual public key: {actual_pub_key}")

        if expected_pub_key == actual_pub_key:
            logging.info("Client public key matches the expected public key. Successfully connected!")
            return True
        else:
            logging.error("Client public key does not match the expected public key.")
            return False
    except Exception as e:
        logging.error(f"Error verifying public key: {e}")
        return False

def convert_to_pem(binary_cert):
    pem_cert = "-----BEGIN CERTIFICATE-----\n"
    pem_cert += base64.b64encode(binary_cert).decode('utf-8')
    pem_cert += "\n-----END CERTIFICATE-----\n"
    return pem_cert

def handle_apparatus(apparatusId, proxy_port, janus_port, expected_cert_pem, stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, proxy_port))
    logging.info(f"proxyApp listening on {LISTEN_IP}:{proxy_port} for Apparatus {apparatusId}")

    conn = SSLConnection(sock, keyfile='cert/proxy.key', certfile='cert/proxy.pem',
                         server_side=True, ssl_version=PROTOCOL_DTLSv1_2,
                         ca_certs='cert/ca.pem', cert_reqs=ssl.CERT_REQUIRED)

    while not stop_event.is_set():
        try:
            conn.listen()
            client_conn, addr = conn.accept()
            logging.info(f"Connection from {addr} for ApparatusID {apparatusId}")

            client_cert_bin = client_conn.getpeercert(binary_form=True)
            logging.debug(f"Client certificate (binary form): {client_cert_bin}")

            client_cert_pem = convert_to_pem(client_cert_bin)
            logging.debug(f"Client certificate (PEM form): {client_cert_pem}")

            if not client_cert_pem or not verify_certificate(client_cert_pem, expected_cert_pem):
                logging.error("Certificate verification failed. Closing connection.")
                client_conn.shutdown()
                client_conn.close()
                continue

            logging.info(f"Apparatus ID {apparatusId} is now available.")

            while not stop_event.is_set():
                data = client_conn.read(4096)
                if not data:
                    break
                forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                forward_sock.sendto(data, (FORWARD_IP, janus_port))
        except ssl.SSLError as e:
            logging.error(f"SSL error: {e}")
        except Exception as e:
            if not stop_event.is_set():
                logging.error(f"Exception: {e}")
        finally:
            client_conn.shutdown()
            client_conn.close()

def start_listener(apparatusId, proxy_port, janus_port, expected_cert_pem):
    stop_event = threading.Event()
    thread = threading.Thread(target=handle_apparatus, args=(apparatusId, proxy_port, janus_port, expected_cert_pem, stop_event))
    thread.start()
    return thread, stop_event

def start_proxy():
    config = configparser.ConfigParser()
    config.read('listeners_proxy.cfg')

    global listeners
    listeners = {}

    for apparatusID in config.sections():
        apparatus_cn = config[apparatusID]['apparatus_cn']
        proxy_port = int(config[apparatusID]['proxy_port'])
        janus_port = int(config[apparatusID]['janus_port'])
        expected_cert_pem = config[apparatusID]['expected_cert']

        thread, stop_event = start_listener(apparatusID, proxy_port, janus_port, expected_cert_pem)
        listeners[apparatusID] = (thread, stop_event)

def save_config(config):
    with open('listeners_proxy.cfg', 'w') as configfile:
        config.write(configfile)

@app.route('/add_proxy_config', methods=['POST'])
def add_camera():
    data = request.get_json()
    apparatus_ID = str(data['apparatus_id'])
    apparatus_cn = data['apparatus_cn']
    proxy_port = data['proxy_port']
    janus_port = data['janus_port']
    expected_cert = data['expected_cert']

    config = configparser.ConfigParser()
    config.read('listeners_proxy.cfg')

    if apparatus_ID in config.sections():
        return jsonify({'error': 'Apparatus already exists'}), 400

    config[apparatus_ID] = {
        'apparatus_cn': apparatus_cn,
        'proxy_port': str(proxy_port),
        'janus_port': str(janus_port),
        'expected_cert': expected_cert
    }
    save_config(config)

    thread, stop_event = start_listener(apparatus_ID, proxy_port, janus_port, expected_cert)
    listeners[apparatus_ID] = (thread, stop_event)

    return jsonify({'status': 'Apparatus proxy configuration added'}), 200

@app.route('/remove_proxy_config', methods=['POST'])
def remove_camera():
    data = request.get_json()
    apparatus_id = str(data['apparatus_id'])

    config = configparser.ConfigParser()
    config.read('listeners_proxy.cfg')

    if apparatus_id not in config.sections():
        return jsonify({'error': 'Apparatus not found'}), 404

    del config[apparatus_id]
    save_config(config)

    if apparatus_id in listeners:
        thread, stop_event = listeners.pop(apparatus_id)
        stop_event.set()
        thread.join()

    return jsonify({'status': 'Apparatus proxy information removed'}), 200

if __name__ == "__main__":
    start_proxy()
    app.run(port=5000)

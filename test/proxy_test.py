import configparser
import socket
import ssl
import logging
import base64
from dtls import do_patch
from dtls.sslconnection import SSLConnection, PROTOCOL_DTLSv1_2
from OpenSSL import crypto

do_patch()

# Configuration
LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 8443
FORWARD_IP = '127.0.0.1'
FORWARD_PORT = 6000

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

config = configparser.ConfigParser()
config.read('listeners_proxy_forTest.cfg')

for apparatusID in config.sections():
    expected_cert_pem = config[apparatusID]['expected_cert']

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

def verify_certificate(client_cert_pem):
    try:
        expected_pub_key = extract_public_key(expected_cert_pem)
        logging.debug(f"Expected public key: {expected_pub_key}")
        actual_pub_key = extract_public_key(client_cert_pem)
        logging.debug(f"Actual public key: {actual_pub_key}")

        if expected_pub_key == actual_pub_key:
            logging.info("Client public key matches the expected public key.")
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

def start_proxy():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    logging.info(f"proxyApp listening on {LISTEN_IP}:{LISTEN_PORT}")

    conn = SSLConnection(sock, keyfile='testCert/proxy.key', certfile='testCert/proxy.pem',
                         server_side=True, ssl_version=PROTOCOL_DTLSv1_2,
                         ca_certs='testCert/ca.pem', cert_reqs=ssl.CERT_REQUIRED)

    while True:
        try:
            conn.listen()
            client_conn, addr = conn.accept()
            logging.info(f"Connection from {addr}")

            client_cert_bin = client_conn.getpeercert(binary_form=True)
            logging.debug(f"Client certificate (binary form): {client_cert_bin}")

            client_cert_pem = convert_to_pem(client_cert_bin)
            logging.debug(f"Client certificate (PEM form): {client_cert_pem}")

            if not client_cert_pem or not verify_certificate(client_cert_pem):
                logging.error("Certificate verification failed. Closing connection.")
                client_conn.shutdown()
                client_conn.close()
                continue

            while True:
                data = client_conn.read(4096)
                if not data:
                    break

                logging.info(f"Received data: {data.decode('utf-8')}")

                # Forward the data
                forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                forward_sock.sendto(data, (FORWARD_IP, FORWARD_PORT))
        except ssl.SSLError as e:
            logging.error(f"SSL error: {e}")
        except Exception as e:
            logging.error(f"Exception: {e}")
        finally:
            client_conn.shutdown()
            client_conn.close()

if __name__ == "__main__":
    start_proxy()

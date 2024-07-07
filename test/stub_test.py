import socket
import ssl
import time

from dtls import do_patch
from dtls.sslconnection import SSLConnection, PROTOCOL_DTLSv1_2

do_patch()

SERVER_IP = '127.0.0.1'
SERVER_PORT = 8443
LOCAL_IP = '127.0.0.1'
LOCAL_PORT = 5001

def handle_ffmpeg_input(dtls_sock):
    local_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    local_sock.bind((LOCAL_IP, LOCAL_PORT))

    while True:
        data, addr = local_sock.recvfrom(4096)
        if not data:
            break
        dtls_sock.write(data)

    local_sock.close()

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    conn = SSLConnection(sock, keyfile='testCert/stub.key', certfile='testCert/stub.pem',
                         ssl_version=PROTOCOL_DTLSv1_2, ca_certs='testCert/ca.pem',
                         cert_reqs=ssl.CERT_REQUIRED)

    try:
        conn.connect((SERVER_IP, SERVER_PORT))
        conn.do_handshake()
        print("Handshake successful.")

        test_payload = b"Stub Application says hello!"
        while True:
            conn.write(test_payload)
            time.sleep(1)

    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except Exception as e:
        print(f"Exception: {e}")
    finally:
        conn.shutdown()
        sock.close()

if __name__ == "__main__":
    main()

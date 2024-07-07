# To run Stub Application you need the following files:
#  -> "cert/stub.key" - client certificate private key
#  -> "cert/stub.pem" - client certificate public part, that is expected in Proxy Application
#  -> "cert/ca.pem"     - ca certificate public part
import configparser
import socket
import threading
import ssl
from dtls import do_patch
from dtls.sslconnection import SSLConnection, PROTOCOL_DTLSv1_2

do_patch()

config = configparser.ConfigParser()
config.read('video-stream.ini')
for PROXY in config.sections():
    PROXY_SERVER_IP = config[PROXY]['proxy_server_ip']
    LOCAL_FFMPEG_IP = config[PROXY]['ffmpeg_ip_listening']
    PROXY_SERVER_PORT = int(config[PROXY]['proxy_server_port'])
    FFMPEG_LISTENING_PORT = int(config[PROXY]['video_port'])   # shared variable between 'video-stream.sh' and stub application

def handle_ffmpeg_input(dtls_sock):
    local_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    local_sock.bind((LOCAL_FFMPEG_IP, FFMPEG_LISTENING_PORT))

    while True:
        data, addr = local_sock.recvfrom(4096)
        if not data:
            break
        dtls_sock.write(data)

    local_sock.close()

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    conn = SSLConnection(sock, keyfile='cert/stub.key', certfile='cert/stub.pem',
                         ssl_version=PROTOCOL_DTLSv1_2, ca_certs='cert/ca.pem',
                         cert_reqs=ssl.CERT_REQUIRED)

    try:
        conn.connect((PROXY_SERVER_IP, PROXY_SERVER_PORT))
        conn.do_handshake()
        print("Handshake successful.")

        ffmpeg_thread = threading.Thread(target=handle_ffmpeg_input, args=(conn,))
        ffmpeg_thread.start()
        ffmpeg_thread.join()
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except Exception as e:
        print(f"Exception: {e}")
    finally:
        conn.shutdown()
        sock.close()

if __name__ == "__main__":
    main()

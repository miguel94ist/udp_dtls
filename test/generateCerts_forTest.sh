# Generate CA key and certificate
mkdir testCert
openssl genrsa -out testCert/ca.key 2048
openssl req -x509 -new -nodes -key testCert/ca.key -sha256 -days 365 -out testCert/ca.pem -subj "/C=PT/ST=Lisbon/L=Lisbon/O=FREE/OU=PROXY/CN=CA"

# Generate Proxy Application key and certificate
openssl genrsa -out testCert/proxy.key 2048
openssl req -new -key testCert/proxy.key -out testCert/proxy.csr -subj "/C=PT/ST=Lisbon/L=Lisbon/O=FREE/OU=PROXY/CN=ProxyApplication"
openssl x509 -req -in testCert/proxy.csr -CA testCert/ca.pem -CAkey testCert/ca.key -CAcreateserial -out testCert/proxy.pem -days 365 -sha256

# Generate Stub Application key and certificate
openssl genrsa -out testCert/stub.key 2048
openssl req -new -key testCert/stub.key -out testCert/stub.csr -subj "/C=PT/ST=Lisbon/L=Lisbon/O=FREE/OU=PROXY/CN=StubApplication"
openssl x509 -req -in testCert/stub.csr -CA testCert/ca.pem -CAkey testCert/ca.key -CAcreateserial -out testCert/stub.pem -days 365 -sha256


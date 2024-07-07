# Generate CA key and certificate
mkdir cert
openssl genrsa -out cert/ca.key 2048
openssl req -x509 -new -nodes -key cert/ca.key -sha256 -days 365 -out cert/ca.pem -subj "/C=PT/ST=Lisbon/L=Lisbon/O=FREE/OU=PROXY/CN=CA"

# Generate Proxy Application key and certificate
openssl genrsa -out cert/proxy.key 2048
openssl req -new -key cert/proxy.key -out cert/proxy.csr -subj "/C=PT/ST=Lisbon/L=Lisbon/O=FREE/OU=PROXY/CN=ProxyApplication"
openssl x509 -req -in cert/proxy.csr -CA cert/ca.pem -CAkey cert/ca.key -CAcreateserial -out cert/proxy.pem -days 365 -sha256

# Generate Stub Application key and certificate
openssl genrsa -out cert/stub.key 2048
openssl req -new -key cert/stub.key -out cert/stub.csr -subj "/C=PT/ST=Lisbon/L=Lisbon/O=FREE/OU=PROXY/CN=StubApplication"
openssl x509 -req -in cert/stub.csr -CA cert/ca.pem -CAkey cert/ca.key -CAcreateserial -out cert/stub.pem -days 365 -sha256


mkdir ../src/proxy/cert
cp cert/proxy.key ../src/proxy/cert
cp cert/proxy.pem ../src/proxy/cert
cp cert/ca.pem ../src/proxy/cert

mkdir ../src/stub/cert
cp cert/stub.key ../src/stub/cert
cp cert/stub.pem ../src/stub/cert
cp cert/ca.pem ../src/stub/cert

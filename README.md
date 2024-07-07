1. Run 'install/generateCert.sh'. In 'install/cert/' are all the necessary certificates for backup. The script will copy the necessary files for the respective folders in Proxy and Stub Applications.

2. In FREE Project copy the following files from 'install/cert/' to 'FREE_WEB/free/videoConfig/Certificates' (create folder if needed), so that FREE can generate the certificates and communicate to Proxy the expected public key:
   - ca.key
   - ca.pem

3. Start Proxy Application.

4. In Free Front-End, create a new VideoConfig.
Verify Proxy configuration file ('src/proxy/listeners_proxy.cfg') for the configuration generated by FREE consuming Proxy REST Endpoints.

5. Replace the content of 'src/stub/certs/stub.key' and 'src/stub/certs/stub.pem' with the content from the VideoConfig Front-End.
Start Stub Application (and video-stream.sh).
Proxy Application should log this (ex: ApparatusID 30):
      -  .....
      -  INFO - Client public key matches the expected public key. Successfully connected!
      -  INFO - Apparatus ID 30 is now available.
      -  .....

6. Open video on Front-End.


--------------------------
Proxy Application has REST Endpoints on port 5000. The value can be changed in the last line of 'proxy.py' (need to change on FREE VideoConfig backend too)
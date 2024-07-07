To execute the test:
1. Run 'generateCerts_forTest.sh'
2. Run Proxy Test Application, Run Stub Test Application. Will fail, Proxy expects a different public key than what's inside 'listeners_proxy_forTest.cfg' in 'expected_cert'
3. Update the 'expected_cert' in 'listeners_proxy_forTest.cfg' with the content of file in 'testCerts/stub.pem', generated in Step 1.
4. Run Proxy Test Application, Run Stub Test Application.
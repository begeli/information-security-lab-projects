import requests
from requests.exceptions import ConnectionError
enclave_retries = 3
while enclave_retries > 0:
    try:
        rep = requests.get("http://127.0.0.1:37100")
        print(rep.text)
        if rep.status_code == 200:
            open('/home/isl/t2/ok_enclave','w').close()
        enclave_retries = 0
    except ConnectionError:
        print("ERROR: An error occurred while connecting to the Enclave process. This is most likely because the enclave process is not running. Execute lsof -P -i -n | grep LISTEN and check if the process is listening on port 37100. If not restart the processes by running /home/isl/t2/run.sh")
        enclave_retries = enclave_retries - 1
        if enclave_retries > 0:
            print("Retrying")

peripheral_retries = 3
while peripheral_retries > 0:
    try:
        rep = requests.get("http://127.0.0.1:37200")
        print(rep.text)
        if rep.status_code == 200:
            open('/home/isl/t2/ok_peripheral','w').close()
        peripheral_retries = 0
    except ConnectionError:
        print("ERROR: An error occurred while connecting to the Peripheral process. This is most likely because the enclave process is not running. Execute lsof -P -i -n | grep LISTEN and check if the process is listening on port 37200. If not restart the processes by running /home/isl/t2/run.sh")
        peripheral_retries = peripheral_retries - 1
        if peripheral_retries > 0:
            print("Retrying")
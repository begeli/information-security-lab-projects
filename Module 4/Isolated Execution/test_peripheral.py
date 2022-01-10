import requests

url = "http://127.0.0.1:4450"
data = "SYN?"
expect = "ACK!"
device = "Peripheral"

def doHealtchCheck():
    try:
        ret = requests.post(url, data)
        print("Received "+ ret.text)
        if(expect in ret.text):
            print(device + " HealthCheck successful!")
        else:
            print(device + " seems to be offline, response unplausible...")
    except:
        print(device + " seems to be offline, POST request unsuccessful...")

doHealtchCheck()
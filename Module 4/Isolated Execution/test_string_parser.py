import requests

url = "http://127.0.0.1:5111"
data = "SYN?"
expect = "ACK!"
device = "StringParser"

def doHealtchCheck():
    try:
        ret = requests.post(url, data)
        print("Received "+ ret.text)
        if(expect in ret.text):
            print("StringParser listening on: " + url)
            print(device + " HealthCheck successful!")
        else:
            print(device + " seems to be offline, response unplausible...")
    except:
        print(device + " seems to be offline, POST request unsuccessful...")

doHealtchCheck()
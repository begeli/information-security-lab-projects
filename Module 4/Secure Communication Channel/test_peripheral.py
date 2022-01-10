import requests

rep = requests.get("http://127.0.0.1:37200")
print(rep.text)
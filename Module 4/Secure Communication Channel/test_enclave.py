import requests

rep = requests.get("http://127.0.0.1:37100")
print(rep.text)
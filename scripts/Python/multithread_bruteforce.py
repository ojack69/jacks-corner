#!/usr/bin/env python3

import requests
import sys
import re
from itertools import islice
import threading
import time

SIGNAL=False

def get_cookie(headers):
    set_cookie = headers['Set-Cookie']
    if not set_cookie:
        print('Failed to get session cookie')
        exit(-1)
    return set_cookie.split(';')[0].split('=')[-1]


def get_csrf(content):
    r_csrf = re.search(r"name=\"csrf\" value=\"([A-Za-z0-9]+)\"", content.decode("utf-8"))
    if not r_csrf:
        print('Failed to get CSRF token')
        exit(-1)
    return r_csrf.groups()[0]

def worker(lines):
    global SIGNAL
    for line in lines:
        line = line.strip()
        # DO STUFF
        print(line)
        if SIGNAL:
            exit(1)
        time.sleep(0.1)



if __name__=='__main__':
    
    with open('lines.txt','r') as lines:
        #worker(lines)
        for chunk in iter(lambda: tuple(islice(lines, int(sys.argv[2]))), ()):
            r = threading.Thread(target=worker, args=(chunk,))
            r.start()
 


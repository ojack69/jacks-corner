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
    
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip,port))
                s.recv(1024)
                
                print("Fuzzing with {} bytes".format(len(payload) - len(prefix)))
                s.send(bytes(payload,"latin-1"))
                s.recv(1024)
        except BaseException as ex:
            print(ex)
            print("Fuzzing crashed at {} bytes".format(len(payload) - len(prefix)))
            sys.exit(0)
        payload += size * "A"
        time.sleep(1)

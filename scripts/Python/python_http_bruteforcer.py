import requests
import string
import sys
import time
def check_challenge(challenge):
    # TODO Implement check function
    return True

if __name__=='__main__':
    result=''
    is_alive=True
    while is_alive:
        print('Bruteforcing: ' + result, end='\r')
        for char in string.printable[0:-7] + ' ': #Ignore bad bytes and newlines/returns/tabs
           if check_challenge(result+char):
                result= result + char
                is_alive = True
                break
           else:
                print('Bruteforcing: ' +result + char, end='\r')
                is_alive = False
        time.sleep(0.3)

    print('Result is: ' + result)


#! /usr/env/python3

import requests
import itertools
import string
import time

def get_pin_guesses(length=4):
    return list(map(lambda x: "".join(x),list(itertools.product(string.digits, repeat=length))))


def pre_action(challenge=None):
    pass

def action(challenge):
    if challenge == '0020':
        return True, False
    return False, False

if __name__ == '__main__':
    do_preaction = True
    reset = False
    found = False
    sleep_time = 0.1
    pin_guesses = get_pin_guesses()

    while not found:
        for x in pin_guesses:
            print(f"[>] Bruteforcing: {x}", end='\r')

            if do_preaction:
                pre_action()

            found, do_preaction = action(x)
            if found:
                break
            else:
                time.sleep(sleep_time)
    print()
    print(f"[!] Found: {x}")



#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import threading
import subprocess

threads = []

hash = '$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.'
bulk = []
max_threads = 50

def check(guess):
    # edit there to change check method
    #return subprocess.run(['php','-r',u'"crypt(\"'+guess+'\"), \"$1$\xf0\x9f\xa7\x82llol$\""'], stdout=subprocess.PIPE)
    return subprocess.check_output(['php','-r','echo crypt(\''+guess+'\', \'$1$🧂llol$\');']).strip()



def cracker(bulk, hash):
    for guess in bulk:
        if check(guess) == hash:
            print('FOUND! : {}'.format(guess))
            for thread in threads:
                thread.join()

with open('/usr/share/wordlists/rockyou.txt','r') as wordlist_file:
    wordlist = list(wordlist_file)
    t = len(wordlist) / max_threads 
    bulk_size = int(t) if t > 0 else len(wordlist)

    for guess in wordlist:
        bulk.append(guess.strip())

        if len(bulk) == bulk_size:
            thread = threading.Thread(target=cracker, args=(bulk[:], hash))
            thread.start()
            bulk = []

if len(bulk) > 0:
     thread = threading.Thread(target=cracker, args=(bulk, hash))
     thread.start()
     threads.append(thread)


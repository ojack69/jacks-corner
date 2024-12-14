"""
This is a template script! Fill the two placeholder at line 25 and 101 with adequate code logic.

Example scenario: Blind SQL Injection

Instead of bruteforcing all characters, first deduct the data to be exfiltrated structure in regex terms, the bruteforce each character based on the structure.

The structure is comprised by one or more of this symbols:
    - l = lowercase char -  [a-z]
    - U = uppercase char - [A-Z]
    - n = number - [0-9]
    - s = symbol - [^A-Za-z0-9]

Example:
    Data to exfiltrate= !Jack69!
    > python http_regex_bruteforcer.py
    >> [>] Enumerating structure: sUlllnns
    >> [>] Enumerated structure in 19 iterations
    >>
    >> [!] Result: !Jack69!
    >> [!] Completed in 191 iterations
"""

from string import ascii_lowercase, ascii_uppercase, digits

symbols = '\'"()$%/\\:.;,_#+*{}[]?|^!'
demo_data = "#SVRpeZE$7qHYRN842#lCYWhVepD3tT3xpgTJP^Q6hzH7ZXKjDgUPT&jjnDAVswP$D!4a#gyV2nX$a5%$EcMwBMQTc$njt8D7m#GNxn@#aUmA6A!2uXTXtBBkYgTLZvr"
class Matcher:
    def __init__(self):
        self.payload = '^'
        self._payload = '^'
        self.structure = ''

    def do_action(self):
        # Implement exfiltration logic here (ex: SQL injection)
        import re
        data = demo_data
        regex = re.compile(self._payload)
        return regex.match(data) is not None


    def is_x(self, check):
        self._payload += check
        res = self.do_action()
        
        if not res:
            self._payload = self.payload
        else:
            self.payload = self._payload
        return res

    def is_lowercase(self):
        return self.is_x('[a-z]')
    
    def is_uppercase(self):
        return self.is_x('[A-Z]')
    
    def is_number(self):
        return self.is_x('[0-9]')

    def is_symbol(self):
        return self.is_x('[^a-zA-Z0-9]')

    def is_done(self):
        return self.is_x('$')

if __name__ == '__main__':
    done = False
    n_iterations = 0
    guess = ''
    matcher = Matcher()
    controls = {
            'l': matcher.is_lowercase, 
            'U': matcher.is_uppercase, 
            'n': matcher.is_number, 
            's': matcher.is_symbol
            }

    sets = {
            'l': ascii_lowercase,
            'U': ascii_uppercase,
            'n': digits,
            's': symbols[:]
            }
    
    while not done:
        for key, control in controls.items():
            n_iterations += 1
            if control():
                matcher.structure += key
                print(f"[>] Enumerating structure: {matcher.structure}", end="\r")
                break
        done = matcher.is_done()
    
    print()
    print(f"[>] Enumerated structure in {n_iterations} iterations")
    
    for _, s in enumerate(matcher.structure):
        for c in sets[s]:
            n_iterations += 1
            # Implement exfiltration logic here (ex: SQL injection)
            print(f'[>] {guess+c}', end='\r')
            data = demo_data
            if data[_] == c:
                guess += c
            
    print(f"[!] Result: {guess}")
    print(f"[!] Completed in {n_iterations} iterations")


    



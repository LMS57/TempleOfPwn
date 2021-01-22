from pwn import *

p = process('chapter1')

def send(a,b=':'):
    p.sendlineafter(b,str(a))

def send2(a,b=':'):
    p.sendafter(b,str(a))

def create(size,data):
    send(1,'>>')
    send(size)
    send(data)

def edit(index,data):
    send(2,'>>')
    send(index)
    send(data)

def delete(index):
    send(3,'>>')
    send(index)


gdb.attach(p)
p.interactive()

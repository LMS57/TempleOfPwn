from pwn import *


def send(a,b=':'):
    p.sendlineafter(b,str(a))

def new(size, content):
    send(1, '>>')
    send(size)
    send(content)

def show(index):
    send(2,'>>')
    send(index)

def edit(index,append,input):
    send(3, '>>')
    send(index)
    send(append, '?')
    send(input)

def delete(index):
    send(4, '>>')
    send(index)

p = process('./note2')




gdb.attach(p)
p.interactive()

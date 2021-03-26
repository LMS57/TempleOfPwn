#!/bin/bash

gcc -static exploit.c -o exploit
cp exploit tmp
cd tmp

rm initramfs.cpio 
find . | cpio -o -H newc > initramfs.cpio
cd ..


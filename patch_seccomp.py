#!/usr/bin/env python

import lief, os
from pwn import *
from subprocess import Popen, PIPE

shell_seccomp_x86_pie = '''
push edi
push esi
push eax
push ebx
push ecx
push edx
push   ebp
mov    ebp, esp
push 	0
pop edi
push 	0
pop esi
push 	0
pop edx
push   0x1
pop ecx
push   38
pop ebx
xor    eax, eax
mov    al, 0xac
int 0x80
push   22
pop    ebx
call get_ip
and eax, 0xfffff000
lea    edx, [eax]
push   edx 
push   %d
mov    edx, esp
push   0x2
pop    ecx
xor    eax, eax
mov    al, 0xac
syscall
leave
pop edx
pop ecx
pop ebx
pop eax
pop esi
pop edi
call get_ip
and eax, 0xfffff000
sub eax, %d
add eax, %d
jmp eax
get_ip:
  pop eax
  jmp eax'''

shell_seccomp_x86 = '''
push edi
push esi
push eax
push ebx
push ecx
push edx
push   ebp
mov    ebp, esp
push 	0
pop edi
push 	0
pop esi
push 	0
pop edx
push   0x1
pop ecx
push   38
pop ebx
xor    eax, eax
mov    al, 0xac
int 0x80
push   22
pop    ebx
call get_ip
and eax, 0xfffff000
lea    edx, [eax]
push   edx 
push   %d
mov    edx, esp
push   0x2
pop    ecx
xor    eax, eax
mov    al, 0xac
syscall
leave
pop edx
pop ecx
pop ebx
pop eax
pop esi
pop edi
mov eax, %d
jmp eax
get_ip:
  pop eax
  jmp eax'''

shell_seccomp = '''
push rdi
push rsi
push rax
push rcx
push rdx
push r8
push r10
push   rbp
mov    rbp, rsp
push   38
pop    rdi	
push   0x1
pop    rsi
xor	 rdx, rdx
xor rcx, rcx
xor r10, r10
xor r8, r8
xor    rax, rax
mov    al, 0x9d
syscall
push   22
pop    rdi
call get_ip
and rax, 0xfffffffffffff000
lea    rdx, [rax]
push   rdx 
push   %d
mov    rdx, rsp
push   0x2
pop    rsi
xor    rax, rax
mov    al, 0x9d
xor rcx, rcx	
xor r8, r8
syscall
leave
pop r10
pop r8
pop rdx
pop rcx
pop rax
pop rsi
pop rdi
mov rax, %d
jmp rax
get_ip:
  pop rax
  jmp rax'''

shell_seccomp_pie = '''
push rdi
push rsi
push rax
push rcx
push rdx
push r8
push r10
push   rbp
mov    rbp, rsp
push   38
pop    rdi	
push   0x1
pop    rsi
xor	 rdx, rdx
xor rcx, rcx
xor r10, r10
xor r8, r8
xor    rax, rax
mov    al, 0x9d
syscall
push   22
pop    rdi
call get_ip
and rax, 0xfffffffffffff000
lea    rdx, [rax]
push   rdx 
push   %d
mov    rdx, rsp
push   0x2
pop    rsi
xor    rax, rax
mov    al, 0x9d
xor rcx, rcx	
xor r8, r8
syscall
leave
pop r10
pop r8
pop rdx
pop rcx
pop rax
pop rsi
pop rdi
call get_ip
and rax, 0xfffffffffffff000
sub rax, %d
add rax, %d
jmp rax
get_ip:
  pop rax
  jmp rax'''
blacklist=['mmap', 'mprotect','rt_sigreturn','connect','bind','open','dup2','symlink','fork','sendfile','vfork','openat','execve','execveat']
whitelist = []

def write_file(filename,content):
	fd=open(filename,'w')
	fd.write(content)
	fd.close()

def convert(code, flag = 1):
	if flag == 1:
		assembly = asm(code, arch='amd64')
	else:
		assembly = code
	ret = [ord(c) for c in assembly]
	return ret

def generate_seccomp(x86):
	if x86:
		template="A = arch\nA == ARCH_i386 ? next: dead\nA = sys_number\n"
	else:
		template="A = arch\nA == ARCH_X86_64 ? next: dead\nA = sys_number\n"
	for sn in blacklist:
		if sn not in whitelist:
			template+="A == {} ? dead : next\n".format(sn)
	template+="ok:\nreturn ALLOW\ndead:\nreturn KILL"
	write_file("scmp.asm",template)
	p=Popen(["seccomp-tools", "asm", "scmp.asm", "-f", "raw"],stdout=PIPE, stderr=PIPE)
	stdout, stderr = p.communicate()
	os.remove("scmp.asm")
	return stdout

def patch_binary(binary, x86):
	sc=generate_seccomp(x86)
	b = lief.parse(binary)
	entrypoint = b.header.entrypoint
	print("entrypoint: 0x%x"%entrypoint)
	code = lief.ELF.Section()
	code += lief.ELF.SECTION_FLAGS.EXECINSTR
	code += lief.ELF.SECTION_FLAGS.WRITE
	if x86:
		code.content = convert(sc, 0) + convert(shell_seccomp_x86%( len(sc)/8, entrypoint))		
	else:
		code.content = convert(sc, 0) + convert(shell_seccomp%( len(sc)/8, entrypoint))
	new_code = b.add(code)
	addr_new_code = new_code.virtual_address
	print("new entrypoint: 0x%x" % (addr_new_code + len(sc) ))
	# b.header.entrypoint = addr_new_code + len(sc) 
	os.system("rm -f %s_patched"%binary)
	b.write("%s_patched"%binary)
	os.system("chmod +x %s_patched"%binary)

def patch_pie(binary, x86):
	sc=generate_seccomp(x86)
	b = lief.parse(binary)
	entrypoint = b.header.entrypoint
	print("entrypoint: 0x%x"%entrypoint)
	code = lief.ELF.Section()
	# code += lief.ELF.SECTION_FLAGS.EXECINSTR
	# code += lief.ELF.SECTION_FLAGS.WRITE
	code.content=[0x90]*0x10
	new_code = b.add(code)
	new_entrypoint = b.header.entrypoint
	print("entrypoint: 0x%x"%new_entrypoint)
	addr_new_code = new_code.virtual_address
	if x86:
		new_code.content = convert(sc, 0) + convert(shell_seccomp_x86_pie%( len(sc)/8, addr_new_code , new_entrypoint))
	else:
		new_code.content = convert(sc, 0) + convert(shell_seccomp_pie%( len(sc)/8, addr_new_code , new_entrypoint))
	b.header.entrypoint = addr_new_code + len(sc) 	
	print("new entrypoint: 0x%x" % (addr_new_code + len(sc) ))
	os.system("rm -f %s_patched"%binary)
	b.write("%s_patched"%binary)
	os.system("chmod +x %s_patched"%binary)

def menu():
	m='0. patch\t'
	for i in range(len(blacklist)):
		m+="%d. %s\t"%(i+1,blacklist[i])
	print(m)

def main(argv):
	if len(argv) <=3:
		print("no")
		return
	binary=argv[1]
	pie = 0
	x86 = 0
	c = ''
	while c!='0':
		try:
			menu()
			c = raw_input("choice: ").strip("\n")
			if c == '0':
				break
			if not c.isdigit():
				return
			i = int(c) -1
			if i >= len(blacklist):
				print("out of range")
				return
			whitelist.append(blacklist[i])
		except Exception as e:
			print(e)
	if argv[1] == '1':
		pie = 1
	if argv[2] == '1':
		x86 = 1

	if pie:
		patch_pie(binary, x86)
	else:
		patch_binary(binary, x86)

if __name__=="__main__":
	main(sys.argv)

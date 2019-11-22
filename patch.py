# python3
import argparse
from lief import PE, ELF, parse
import sys
import struct
from capstone import *
from keystone import *


class Shellcode():
    def __init__(self, arch):
        self.arch = arch
        if arch == 'x86':
            self.engine = Ks(KS_ARCH_X86, KS_MODE_32)
            self._jmp = 'jmp %d'
            self._save_state = 'pushf; push eax; push ebx; push ecx; push edx; push esi; push edi; push ebp'
            self._restore_state = 'pop ebp; pop edi; pop esi; pop edx; pop ecx; pop ebx; pop eax; popf'
        elif arch == 'x64':
            self.engine = Ks(KS_ARCH_X86, KS_MODE_64)
            # self._jmp = 'jmp [rip]'
            self._jmp = 'jmp %d'
            self._save_state = 'pushf; push rax; push rbx; push rcx; push rdx; push rsi; push rdi; push rbp; push r8; push r9; push r10; push r11; push r12; push r13; push r14; push r15'
            self._restore_state = 'pop r15; pop r14; pop r13; pop r12; pop r11; pop r10; pop r9; pop r8; pop rbp; pop rdi; pop rsi; pop rdx; pop rcx; pop rbx; pop rax; popf'

    def jmp(self, _from, _to):
        shellcode = None
        if self.arch == 'x86':
            offset = _to - _from
            shellcode, _ = self.engine.asm(self._jmp % offset)
        elif self.arch == 'x64':
            offset = _to - _from
            shellcode, _ = self.engine.asm(self._jmp % offset)
            # shellcode += list(struct.pack('<Q', _to))
        return shellcode

    @property
    def save_state(self):
        return self.engine.asm(self._save_state)[0]

    @property
    def restore_state(self):
        return self.engine.asm(self._restore_state)[0]


def main():
    parser = argparse.ArgumentParser(description='Static hook binary')
    parser.add_argument('file', metavar='FILE', type=str, help='Executable file path')
    parser.add_argument('-s', '--shellcode', type=str, help='Shellcode file path', required=True)
    parser.add_argument('-e', '--entrypoint', action='store_false', help='Hook at entrypoint')
    parser.add_argument('-d', '--data', action='store_true', help='Create data section')
    parser.add_argument('-a', '--address', type=lambda x: int(x, 0), nargs='*', help='Hook at address', default=[])
    t_arg = parser.add_argument('-o', '--output', type=str, help='Output file', default='patched')

    args = parser.parse_args()

    b = parse(args.file)
    t_arg.default = '%s_patched' % args.file
    shellcode = list(open(args.shellcode, 'rb').read())

    section = create_section(b)
    code = add_section(b, section)

    architecture = get_cpu_architecture(b)
    if not architecture:
        print('Unknow architecture. Exit!')
        sys.exit(1)

    if len(args.address) != 0 and len(args.address) == 1:  # hook at address
        for addr in args.address:
            cs_mode = None
            if architecture == 'x86':
                cs_mode = CS_MODE_32
                jmplen = 5
            else:
                cs_mode = CS_MODE_64
                jmplen = 14

            # calculate number of bytes to patch
            md = Cs(CS_ARCH_X86, cs_mode)
            data = b.get_content_from_virtual_address(addr, 20)
            ssum = 0
            for ins in md.disasm(bytes(data), 0x1000):
                ssum += ins.size
                if ssum >= jmplen:
                    break
            original_bytes = data[:ssum]

            section_addr = code.virtual_address
            if is_pefile(b):
                section_addr = code.virtual_address + b.optional_header.imagebase
            # jmp depend on architecture
            sc = Shellcode(architecture)
            jmp_to = sc.jmp(addr, section_addr)
            save_state = sc.save_state
            restore_state = sc.restore_state
            jmp_back = original_bytes + sc.jmp(section_addr + len(shellcode) + len(save_state) + len(restore_state) + ssum, addr + ssum)
            jmp_to += [0x90] * (ssum - len(jmp_to))  # pad nop
            b.patch_address(addr, jmp_to)
            shellcode = save_state + shellcode + restore_state + jmp_back
    elif args.data:
        pass
    elif args.entrypoint:  # hook at entrypoint
        entrypoint = 0
        if is_pefile(b):
            if architecture == 'x64':  # hardcoded address to jump in PE x64
                entrypoint = b.optional_header.addressof_entrypoint + b.optional_header.imagebase
            else:
                entrypoint = b.optional_header.addressof_entrypoint
            b.optional_header.addressof_entrypoint = code.virtual_address
        else:
            entrypoint = b.header.entrypoint
            b.header.entrypoint = code.virtual_address

        sc = Shellcode(architecture)
        save_state = sc.save_state
        restore_state = sc.restore_state
        jmp_back = sc.jmp(code.virtual_address + len(shellcode) + len(save_state) + len(restore_state), entrypoint)
        shellcode = save_state + shellcode + restore_state + jmp_back

    code.content = shellcode
    outfile = args.output if args.output != 'patched' else '%s_patched' % args.file
    print('Create new section at 0x%x' % code.virtual_address)
    b.write(outfile)


def create_section(binary):
    section = None
    if is_pefile(binary):  # PE file
        section = PE.Section()
        section.characteristics = PE.SECTION_CHARACTERISTICS.CNT_CODE | PE.SECTION_CHARACTERISTICS.MEM_READ | PE.SECTION_CHARACTERISTICS.MEM_EXECUTE | PE.SECTION_CHARACTERISTICS.MEM_WRITE
        # section.virtual_size = 0x1000
        section.content = [0x90] * 0x1000
    else:
        section = ELF.Section()
        section += ELF.SECTION_FLAGS.ALLOC
        section += ELF.SECTION_FLAGS.WRITE
        section += ELF.SECTION_FLAGS.EXECINSTR
        section.alignment = 16
        section.content = [0x90] * 0x1000
    return section


def add_section(binary, section):
    result = None
    if is_pefile(binary):
        result = binary.add_section(section)
    else:
        result = binary.add(section)
    return result


def get_cpu_architecture(binary):
    code = None
    if is_pefile(binary):
        code = binary.header.machine
    else:
        code = binary.header.machine_type
    result = None
    if code == PE.MACHINE_TYPES.I386:
        result = 'x86'
    elif code == PE.MACHINE_TYPES.AMD64:
        result = 'x64'
    elif code == ELF.ARCH.i386:
        result = 'x86'
    elif code == ELF.ARCH.x86_64:
        result = 'x64'
    return result


def is_pefile(binary):
    return hasattr(binary, 'dos_header')


if __name__ == '__main__':
    main()

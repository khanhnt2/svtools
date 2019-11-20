# python3
import argparse
from lief import PE, ELF, parse
import sys
import struct
from capstone import *


def main():
    parser = argparse.ArgumentParser(description='Static hook binary')
    parser.add_argument('file', metavar='FILE', type=str, help='Executable file path')
    parser.add_argument('-s', '--shellcode', type=str, help='Shellcode file path', required=True)
    parser.add_argument('-e', '--entrypoint', action='store_false', help='Hook at entrypoint')
    parser.add_argument('-d', '--data', action='store_true', help='Create data section')
    parser.add_argument('-a', '--address', type=lambda x: int(x, 0), help='Hook at address', default=0)
    t_arg = parser.add_argument('-o', '--output', type=str, help='Output file', default='patched')

    # args = parser.parse_args(['..\\test\\python', '-s', 'F:\\tmp\\python_patched'])
    args = parser.parse_args()

    b = parse(args.file)
    t_arg.default = '%s_patched' % args.file
    shellcode = list(open(args.shellcode, 'rb').read())

    section = create_section(b)
    code = add_section(b, section)

    jmp_back = []
    architecture = get_cpu_architecture(b)
    if not architecture:
        print('Unknow architecture. Exit!')
        sys.exit(1)

    if args.address != 0:  # hook at address
        addr = args.address
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

        rva_addr = addr
        jmp_to_addr = code.virtual_address
        if is_pefile(b):
            rva_addr -= b.optional_header.imagebase
            jmp_to_addr = code.virtual_address + b.optional_header.imagebase
        # jmp depend on architecture
        if architecture == 'x86':
            offset = code.virtual_address - rva_addr - 5
            jmp_to = list(b'\xe9' + struct.pack('<I', offset & 0xffffffff))  # jmp offset
            offset = rva_addr + ssum - (code.virtual_address + len(shellcode) + ssum) - 5
            jmp_back = original_bytes + list(b'\xe9' + struct.pack('<I', offset & 0xffffffff))
        else:
            jmp_to = list(b'\xff\x25\x00\x00\x00\x00' + struct.pack('<Q', jmp_to_addr))  # jmp [RIP + 6]
            jmp_back = original_bytes + list(b'\xff\x25\x00\x00\x00\x00' + struct.pack('<Q', addr + ssum))
        jmp_to += [0x90] * (ssum - len(jmp_to))  # patch nop
        b.patch_address(addr, jmp_to)
        push_registers = [0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57]
        pop_register = [0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58]
        shellcode = push_registers + shellcode + pop_register + jmp_back
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
        if architecture == 'x86':
            offset = entrypoint - (code.virtual_address + len(shellcode)) - 5
            jmp_back = list(b'\xe9' + struct.pack('<I', offset & 0xffffffff))
        else:
            jmp_back = list(b'\xff\x25\x00\x00\x00\x00' + struct.pack('<Q', entrypoint))
        push_registers = [0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55]
        pop_register = [0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58]
        shellcode = push_registers + shellcode + jmp_back + pop_register

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

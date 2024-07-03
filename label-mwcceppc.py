#!/usr/bin/python
import sys
import os
import subprocess
import pefile

exe_path = sys.argv[1]
output_path = sys.argv[2]

obj_files = [f for f in os.listdir('.') if f.endswith('.o')]
result = subprocess.run(['nm'] + obj_files, stdout=subprocess.PIPE, text=True, check=True)
available_functions = []
for line in result.stdout.splitlines():
	try:
		available_functions.append(line.split()[2])
	except IndexError:
		pass

pe = pefile.PE(exe_path)

relocations = [entry.rva + 0x400000 for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC
               for entry in base_reloc.entries if entry.type == 3]

address_ranges = []
for section in pe.sections:
	name = section.Name.decode()[1:].rstrip('\x00')
	if name in ['rsrc', 'reloc']:
		continue
	addr = section.VirtualAddress + 0x400000
	address_ranges.append((name, addr, addr + section.Misc_VirtualSize))

exe_imports = [(imp.name.decode('utf-8') if imp.name else imp.ordinal, imp.address)
               for entry in pe.DIRECTORY_ENTRY_IMPORT
               for imp in entry.imports]

def get_value(section_name: str, relative_offset: int) -> bytes:
	with open(f'mwcceppc-{section_name}.bin', 'rb') as fp:
		fp.seek(relative_offset)
		return fp.read(4)

def get_section(addr: int) -> int:
	for i, (_, start, end) in enumerate(address_ranges):
		if start <= addr <= end:
			return i
	raise ValueError(f'No section found for 0x{addr:X}')

def get_section_by_name(name: str) -> int:
	return next(i for i, (curname, _, _) in enumerate(address_ranges) if curname == name)

idata_section = get_section_by_name('idata')
idata_offset = address_ranges[idata_section][1]

resolutions = []
for sym, addr in exe_imports:
	if sym in available_functions:
		dest = sym
	elif sym == 189:
		dest = 'lp_checkin'
	elif sym == 190:
		dest = 'lp_checkout'
	else:
		dest = 'stub_abort'
	resolutions.append((addr - idata_offset, dest))

section_labels = [[] for _ in address_ranges]

# TODO: do this in Python
result = subprocess.run(['winedump', '-j', 'debug', exe_path], stdout=subprocess.PIPE, text=True, check=True)
lines = result.stdout.splitlines()
try:
	idx = lines.index('                           ----- Begin Symbol Table -----')
except ValueError:
	# No debug symbols in this EXE
	pass
else:
	for line in lines[idx+1:len(lines)]:
		if not line:
			break
		split = line.split()
		name = split[4].strip("'")
		if name == '_mainCRTStartup':
			# We define this in mwcceppc-sections.ld
			continue
		section, addr = [int(x, 16) for x in split[5].split(':')]
		section -= 1
		if section == 4 or section >= 8: # .rsrc, .reloc
			continue
		if section > 4:
			section -= 1
		section_labels[section].append((addr, f'"{name}"', False))

already_labeled = set()

for relocation in relocations:
	section = get_section(relocation)
	relative_offset = relocation - address_ranges[section][1]
	dest_addr = int.from_bytes(get_value(address_ranges[section][0], relative_offset), byteorder='little')
	label = f'.L{dest_addr:06X}'
	section_labels[section].append((relative_offset, label, True))
	if dest_addr not in already_labeled:
		dest_section = get_section(dest_addr)
		section_labels[dest_section].append((dest_addr - address_ranges[dest_section][1], label, False))
		already_labeled.add(dest_addr)

for offset, func in resolutions:
	section_labels[idata_section].append((offset, func, True))

for section_label in section_labels:
	section_label.sort(key=lambda x: (x[0], x[2]))

def label_section(i: int) -> str:
	section_name = address_ranges[i][0]
	extra_flags = 'x' if section_name == 'text' else 'w' if section_name in ['data', 'bss'] else ''
	asm = f'.section .{section_name}, "a{extra_flags}"\n'

	incbin_str = f'.incbin "mwcceppc-{section_name}.bin"'
	last_addr = 0

	for cur_addr, label, is_data in section_labels[i]:
		length = cur_addr - last_addr
		if length > 0:
			if section_name != 'bss':
				asm += f'{incbin_str}, 0x{last_addr:x}, 0x{length:x}\n'
			else:
				asm += f'.zero 0x{length:x}\n'

		if is_data:
			asm += f'.int {label}\n'
			last_addr = cur_addr + 4
		else:
			if length < 0:
				asm += f'{label} = . - {abs(length)}\n'
			else:
				asm += f'{label}:\n'
				last_addr = cur_addr

	remaining_length = address_ranges[i][2] - address_ranges[i][1] - last_addr
	if remaining_length > 0:
		if section_name != 'bss':
			asm += f'{incbin_str}, 0x{last_addr:x}\n'
		else:
			asm += f'.zero 0x{remaining_length:x}\n'

	return asm

if len(sys.argv) > 3:
	asm = label_section(get_section_by_name(sys.argv[3]))
else:
	asm = '\n'.join([label_section(i) for i in range(len(address_ranges))])

with open(output_path, 'w') as fp:
	fp.write(asm)

#!/usr/bin/python
import sys
import pefile

exe_path = sys.argv[1]
output_path = sys.argv[2]
entry_name = sys.argv[3] if len(sys.argv) > 3 else '_mainCRTStartup'

pe = pefile.PE(exe_path)

with open(output_path, 'w') as fp:
	start_addr = pe.OPTIONAL_HEADER.ImageBase + pe.sections[0].VirtualAddress
	fp.write(f'. = 0x{start_addr:06X};\n{entry_name} = .;\n')

	for i, section in enumerate(pe.sections):
		name = section.Name.decode()[1:].rstrip('\x00')
		if name == 'rsrc' or name == 'reloc':
			continue

		if i != 0:
			fp.write(f'\n. = {entry_name} + 0x{section.VirtualAddress-0x1000:06X};\n')
		fp.write(f""".{name.lower()} : {'{'}
\tmwcceppc-labeled.o(.{name})
{'}'}\n""")

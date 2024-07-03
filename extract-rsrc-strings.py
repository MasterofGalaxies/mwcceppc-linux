#!/usr/bin/python
import pefile
import sys

def escape_c_string(text):
	escape_dict = {
		'\\': '\\\\',
		'"': '\\"',
		'\n': '\\n',
		'\t': '\\t',
		'\r': '\\r'
	}

	for key, value in escape_dict.items():
		text = text.replace(key, value)

	return text

exe_path = sys.argv[1]
output_path = sys.argv[2]

pe = pefile.PE(exe_path)

string_table = []
for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
	if resource_type.struct.Id == pefile.RESOURCE_TYPE['RT_STRING']:
		for entry in resource_type.directory.entries:
			for resource in entry.directory.entries:
				data = pe.get_data(resource.data.struct.OffsetToData, resource.data.struct.Size)
				strings = []
				offset = 0

				while offset < len(data):
					length = int.from_bytes(data[offset:offset + 2], byteorder='little') * 2
					offset += 2
					string_data = data[offset:offset + length].decode('utf-16le')
					escaped_string = escape_c_string(string_data)
					strings.append(f'"{escaped_string}"')
					offset += length

				index_base = (entry.struct.Id - 1) * 16

				while len(string_table) < index_base:
					string_table.append('NULL')

				string_table.extend(strings)

max_id = max(entry.struct.Id for entry in resource_type.directory.entries)
max_index = max_id * 16
while len(string_table) < max_index:
	string_table.append('NULL')

with open(output_path, 'w') as f:
	f.write('static const char *string_table[] = {\n\t')
	f.write(',\n\t'.join(string_table))
	f.write('\n};\n')

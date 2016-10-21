import os
import sys
sys.path.append('../p4_hlir')
from p4_hlir.main import HLIR
from p4_hlir import hlir
import shutil
import math


p4_source = sys.argv[1]
absolute_source = os.path.join(os.getcwd(), p4_source)
if not os.path.isfile(absolute_source):
    print "Source file '" + p4_source + \
          "' could not be opened or does not exist."

input_hlir = HLIR(absolute_source)
input_hlir.build()

# Get a parser_state
for parse_state in input_hlir.p4_parse_states.itervalues():
    if len(parse_state.branch_on) > 0:
        if isinstance(parse_state.branch_on[0], hlir.p4_headers.p4_field):
            if parse_state.branch_on[0].instance.name == "ipv4":
                break
print parse_state

# Fields of the parser state
header_fields = parse_state.branch_on[0].instance.fields
protocol_name = 'p4_' + parse_state.branch_on[0].instance.name
# Write to file
dissector_filename = os.path.dirname(absolute_source) + "/" + "p4_dissector.lua"
shutil.copyfile('p4_dissector_template.lua', dissector_filename)
f = open(dissector_filename, "a")

f.write("\n\n-- Auto generated section\n\n")

f.write('p4_proto = Proto(\"' + protocol_name + '","' + protocol_name.upper()
        + ' Protocol")\n')
f.write('function p4_proto.dissector(buffer,pinfo,tree)\n')
f.write('    pinfo.cols.protocol = "' + protocol_name.upper() + '"\n')
f.write('    local subtree = tree:add(p4_proto,buffer(),"'
        + protocol_name.upper() + ' Protocol Data")\n')

field_offset = 0  # This is in bits

for i, field in enumerate(header_fields):
    field.width  # This is in bits
    field_name = field.name
    byte_offset_str = str(field_offset / 8)
    field_length_str = str(int(math.ceil(field.width / 8.0)))
    buffer_str = 'buffer(' + byte_offset_str + ',' + field_length_str + ')'
    f.write('    subtree:add(' + buffer_str + ',')
    f.write('"' + field_name + ' (' + str(field.width) + ' bits) - "')
    if field.width < 8:
        start_bit = str((field_offset + 1) % 8)
        end_bit = str((field_offset + field.width) % 8)
        if end_bit == '0':
            end_bit = '8'
        f.write(' .. "Binary: " .. ')
        f.write('tobits(' + buffer_str + ':uint(), 8, ' + start_bit
                + ', ' + end_bit + ')')
    else:
        f.write(' .. "Hex: " .. ')
        start_bit = str(field_offset % 8)
        end_bit = str(field.width)
        bytecount = str(int(math.ceil(field.width / 4)))

        f.write('string.format("%0' + bytecount + 'X"' + ',' + buffer_str
                + ':bitfield(' + start_bit + ', ' + end_bit + '))')

    f.write(')\n')
    field_offset += field.width

f.write('end\n\n')
f.write('my_table = DissectorTable.get("ethertype")\n')
f.write('my_table:add(0x0800, p4_proto)\n')
f.close()

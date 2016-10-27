# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import shutil
import math
import argparse
from p4_hlir.main import HLIR

# Handle input arguments
arg_parser = argparse.ArgumentParser(description='Create a Wireshark dissector '
                                                 'from a P4 file')
arg_parser.add_argument('p4_source', type=argparse.FileType('r'),
                        help='P4 source file')
arg_parser.add_argument('-d', metavar='destination',
                        help='Destination file. If none given, the destination'
                             ' has the form <pwd>/<p4_source>-<protocol>.lua')
arg_parser.add_argument('-p', metavar="protocol", dest="protocol",
                        help='Protocol in P4 source file for which to build a '
                             'dissector. Use instance rather than header name '
                             '(i.e. without a "_t" at the end). If none is '
                             'given, build a dissector for every protocol.')

args = arg_parser.parse_args()
p4_source = args.p4_source.name
args.p4_source.close()
p4_protocol = args.protocol
absolute_source = os.path.abspath(p4_source)

if args.d is None:
    # Set default filename if the user did not provide one
    dissector_filename = '%s-%s.lua' % (p4_source, p4_protocol)
else:
    # Otherwise, check that the destination path exists, and if yes use it
    # for the output
    destination_path = os.path.dirname(os.path.abspath(args.d))
    if os.path.exists(destination_path):
        dissector_filename = os.path.abspath(args.d)
    else:
        print "Error: Destination path (%s) does not exist." % destination_path
        exit()


# Build HLIR from input
input_hlir = HLIR(absolute_source)
input_hlir.build()

# Get a parser_state
parse_state = None
for parse_state_iterator in input_hlir.p4_parse_states.itervalues():
    # Find the corresponding parser state. "start" doesn't have a
    # latest_extraction so check for that first
    if (parse_state_iterator.name != "start"
            and parse_state_iterator.latest_extraction.name == p4_protocol):
        parse_state = parse_state_iterator
        break
if not parse_state:
    print "Protocol %s not found in %s" % (p4_protocol, absolute_source)
    exit()

# Fields of the parser state
header_fields = parse_state.latest_extraction.fields
protocol_name = 'p4_' + parse_state.latest_extraction.name
previous_protocol_name = parse_state.prev.map.keys()[0].latest_extraction.name
previous_decision_field = \
    parse_state.prev.map.keys()[0].return_statement[1][0].split('.')[1]
previous_decision_value = \
    parse_state.prev.map.keys()[0].return_statement[2][0][0][0][1]
# Write to file
shutil.copyfile('p4_dissector_template.lua', dissector_filename)
f = open(dissector_filename, "a")

# Write the output Lua script
f.write("\n\n-- Auto generated section\n\n")
f.write('p4_proto = Proto(\"' + protocol_name + '","' + protocol_name.upper()
        + ' Protocol")\n')
f.write('function p4_proto.dissector(buffer,pinfo,tree)\n')
f.write('    pinfo.cols.protocol = "' + protocol_name.upper() + '"\n')
f.write('    local subtree = tree:add(p4_proto,buffer(),"'
        + protocol_name.upper() + ' Protocol Data")\n')

field_offset = 0  # This is in bits

for i, field in enumerate(header_fields):
    byte_offset_str = str(field_offset / 8)
    field_length_str = str(int(math.ceil(field.width / 8.0)))
    buffer_str = 'buffer(' + byte_offset_str + ',' + field_length_str + ')'
    f.write('    subtree:add(' + buffer_str + ',')
    f.write('"' + field.name + ' (' + str(field.width) + ' bits) - "')
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

# Register insertion point
dissector_table = previous_decision_field.lower()
insertion_value = str(previous_decision_value).lower()

# Deal with some common cases
if previous_protocol_name == 'ipv4' or 'ipv6' and dissector_table == 'protocol':
    dissector_table = 'ip.proto'
if previous_protocol_name == 'tcp' and dissector_table == 'port':
    dissector_table = 'tcp.port'

f.write('my_table = DissectorTable.get("' + dissector_table + '")\n')
f.write('my_table:add(' + insertion_value + ', p4_proto)\n')
f.close()

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
import sys
import shutil
import math
import argparse
from p4_hlir.main import HLIR


def build_preamble_string(protocol_name):
    return ('\n\n-- Auto generated section\n\n'
            'p4_proto = Proto("%s","%s Protocol")\n'
            'function p4_proto.dissector(buffer,pinfo,tree)\n'
            '    pinfo.cols.protocol = "%s"\n'
            '    local subtree = tree:add(p4_proto,buffer(),"%s Protocol Data")'
            '\n'
            % (protocol_name, protocol_name.upper(), protocol_name.upper(),
               protocol_name.upper()))


def build_field_string(field, offset):
    byte_offset = offset / 8
    byte_width = int(math.ceil(field.width / 8.0))
    buffer_string = 'buffer(%i,%i)' % (byte_offset, byte_width)
    field_string = '%s (%i bits)' % (field.name, field.width)
    if field.width < 8:
        start_bit = (offset + 1) % 8
        end_bit = (offset + field.width) % 8
        if not end_bit:
            end_bit = 8
        format_type = 'Binary'
        format_string = 'tobits(%s:uint(), 8, %i, %i)' \
                        % (buffer_string, start_bit, end_bit)
    else:
        start_bit = offset % 8
        end_bit = field.width
        hex_count = int(math.ceil(field.width / 4.0))
        format_type = 'Hex'
        format_string = 'string.format("%%0%iX", %s:bitfield(%i, %i))' \
                        % (hex_count, buffer_string, start_bit, end_bit)

    return ('    subtree:add(%s, "%s - %s: " .. %s)\n'
            % (buffer_string, field_string, format_type, format_string))


def build_postamble_string(table, value):
    return ('end\n\n'
            'my_table = DissectorTable.get("%s")\n'
            'my_table:add(%s, p4_proto)\n'
            % (table, value))

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
    dissector_filename = '%s-%s.lua' % (os.path.basename(p4_source), p4_protocol)
else:
    # Otherwise, check that the destination path exists, and if yes use it
    # for the output
    destination_path = os.path.dirname(os.path.abspath(args.d))
    if os.path.exists(destination_path):
        dissector_filename = os.path.abspath(args.d)
    else:
        print "Error: Destination path (%s) does not exist." % destination_path
        sys.exit()


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


output_string = build_preamble_string(protocol_name)

field_offset = 0  # This is in bits
for field in header_fields:
    output_string += build_field_string(field, field_offset)
    field_offset += field.width


# Register insertion point
dissector_table = previous_decision_field.lower()
insertion_value = str(previous_decision_value).lower()

# Deal with some common cases
if previous_protocol_name == 'ipv4' or 'ipv6' and dissector_table == 'protocol':
    dissector_table = 'ip.proto'
if previous_protocol_name == 'tcp' and dissector_table == 'port':
    dissector_table = 'tcp.port'

output_string += build_postamble_string(dissector_table, insertion_value)

# Write to file
template_path = os.path.dirname(os.path.realpath(__file__))
template_path += '/p4_dissector_template.lua'
shutil.copyfile(template_path, dissector_filename)
f = open(dissector_filename, "a")
f.write(output_string)
f.close()

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
import collections
from p4_hlir.main import HLIR


def generate_preamble_string(protocol_name):
    return ('\n\n-- Auto generated section\n\n'
            'p4_proto = Proto("%s","%s Protocol")\n'
            'function p4_proto.dissector(buffer,pinfo,tree)\n'
            '    pinfo.cols.protocol = "%s"\n'
            '    local subtree = tree:add(p4_proto,buffer(),"%s Protocol Data")'
            '\n'
            % (protocol_name, protocol_name.upper(), protocol_name.upper(),
               protocol_name.upper()))


def generate_field_string(field, offset):
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


def generate_postamble_string(table, value):
    return ('end\n\n'
            'my_table = DissectorTable.get("%s")\n'
            'my_table:add(%s, p4_proto)\n'
            % (table, value))


def generate_dependencies(input_hlir):
    dependency_dict = collections.defaultdict(list)
    for parse_state in input_hlir.p4_parse_states.itervalues():
        current_protocol = parse_state.name.split('parse_')[-1]
        for branch_value, next_parse_state in parse_state.branch_to.iteritems():
            next_protocol = next_parse_state.name.split('parse_')[-1]
            try:
                branch_field = parse_state.return_statement[1][0].split('.')[1]
                next_protocol_fields = next_parse_state.latest_extraction.fields
                protocol_dependencies = (current_protocol,
                                         branch_field,
                                         branch_value,
                                         next_protocol_fields)
                dependency_dict[next_protocol].append(protocol_dependencies)
            except (AttributeError, IndexError):
                pass
    return dependency_dict


# Handle input arguments
arg_parser = argparse.ArgumentParser(description='Create a Wireshark dissector '
                                                 'from a P4 file')
arg_parser.add_argument('p4_source', type=argparse.FileType('r'),
                        help='P4 source file')
arg_parser.add_argument('-d', metavar='destination',
                        help='Destination file. If none given, the destination'
                             ' has the form <pwd>/<p4_source>-<protocol>.lua')
arg_parser.add_argument('-p', metavar="protocol", dest="protocol",
                        default='all',
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
    dissector_filename = '%s-%s.lua' % (
    os.path.basename(p4_source), p4_protocol)
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

# Generate dependencies
# TODO: Build all dissectors if protocol is 'all'
dependency_dict = generate_dependencies(input_hlir)
if p4_protocol in dependency_dict:
    protocol_name = 'p4_' + p4_protocol
    previous_protocol, decision_field, decision_value, header_fields = \
        dependency_dict[p4_protocol][0]
else:
    print 'Protocol %s does not exist in %s' % (p4_protocol, p4_source)
    sys.exit()

output_string = generate_preamble_string(protocol_name)

field_offset = 0  # This is in bits
for field in header_fields:
    output_string += generate_field_string(field, field_offset)
    field_offset += field.width

# Register insertion point
dissector_table = decision_field.lower()
insertion_value = str(decision_value).lower()

# Deal with some common cases
if previous_protocol == 'ipv4' or 'ipv6' and dissector_table == 'protocol':
    dissector_table = 'ip.proto'
if previous_protocol == 'tcp' and dissector_table == 'port':
    dissector_table = 'tcp.port'

output_string += generate_postamble_string(dissector_table, insertion_value)

# Write to file
template_path = os.path.dirname(os.path.realpath(__file__))
template_path += '/p4_dissector_template.lua'
shutil.copyfile(template_path, dissector_filename)
f = open(dissector_filename, "a")
f.write(output_string)
f.close()

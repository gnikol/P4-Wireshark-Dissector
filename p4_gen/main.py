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
import math
import collections


class ProtocolDissector:

    def __init__(self, protocol):
        self.protocol = protocol
        self.filename = None
        self.output = None

    @staticmethod
    def __generate_field_string(field, offset):
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

    def __generate_preamble_string(self):

        template_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'p4_dissector_template.lua')
        with open(template_path) as template:
            template_string = template.read()

        return ('%s'
                '\n\n-- Auto generated section\n\n'
                'p4_proto = Proto("%s","%s Protocol")\n'
                'function p4_proto.dissector(buffer,pinfo,tree)\n'
                '    pinfo.cols.protocol = "%s"\n'
                '    local subtree = tree:add(p4_proto,buffer(),'
                '"%s Protocol Data")\n'
                % (template_string,
                    self.protocol.protocol_lua_string,
                    self.protocol.protocol_lua_string.upper(),
                    self.protocol.protocol_lua_string.upper(),
                    self.protocol.protocol_lua_string.upper()))

    def __generate_postamble_string(self):
        # Register insertion point
        self.protocol.branch_field.lower()
        self.protocol.branch_value = str(self.protocol.branch_value).lower()

        # Deal with some common cases
        if self.protocol.previous_protocol == 'ipv4' or 'ipv6'\
           and self.protocol.branch_field == 'protocol':
            self.protocol.branch_field = 'ip.proto'
        if self.protocol.previous_protocol == 'tcp'\
           and self.protocol.branch_field == 'port':
            self.protocol.branch_field = 'tcp.port'

        return ('end\n\n'
                'my_table = DissectorTable.get("%s")\n'
                'my_table:add(%s, p4_proto)\n'
                % (self.protocol.branch_field.lower(),
                   self.protocol.branch_value))

    def generate_output(self):

        preamble_string = self.__generate_preamble_string()

        field_offset = 0  # This is in bits
        field_string = ''
        for field in self.protocol.protocol_fields:
            field_string += self.__generate_field_string(field, field_offset)
            field_offset += field.width

        postamble_string = self.__generate_postamble_string()

        self.output = preamble_string + field_string + postamble_string

    def write(self):
        with open(self.filename, "w") as f:
            f.write(self.output)


class Protocol:
    def __init__(self, protocol_name, protocol_fields, previous_protocol,
                 branch_field, branch_value):

        self.protocol_name = protocol_name
        self.protocol_lua_string = 'p4_' + protocol_name
        self.protocol_fields = protocol_fields
        self.previous_protocol = previous_protocol
        self.branch_field = branch_field
        self.branch_value = branch_value


def generate_dependencies(input_hlir):
    dependency_dict = collections.defaultdict(list)
    for parse_state in input_hlir.p4_parse_states.itervalues():
        current_protocol = parse_state.name.split('parse_')[-1]
        for branch_value, next_parse_state \
                in parse_state.branch_to.iteritems():
            next_protocol = next_parse_state.name.split('parse_')[-1]
            try:
                branch_field = parse_state.return_statement[1][0].split('.')[1]
                next_protocol_fields = \
                    next_parse_state.latest_extraction.fields
                protocol = Protocol(next_protocol,
                                    next_protocol_fields,
                                    current_protocol,
                                    branch_field,
                                    branch_value)

                dependency_dict[next_protocol].append(protocol)
            except (AttributeError, IndexError):
                pass
    return dependency_dict

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

"""
test_p4_gen
----------------------------------
Tests for `p4_gen` module.
"""

import pytest
import os
import filecmp
import subprocess


def call_p4_gen_wireshark(options, exec_path=None):
    try:
        if exec_path:
            exec_file = exec_path
        else:
            exec_file = os.path.abspath("../bin/p4-gen-wireshark")
        subprocess.call(str(exec_file) + " " + options, shell=True)
    except Exception as e:
        return e


def test_p4_gen_wireshark_empty():
    # No input arguments
    assert call_p4_gen_wireshark('') != 0


def test_p4_gen_wireshark_wrong_input():
    # Non-existing input
    assert call_p4_gen_wireshark('foo.bar') != 0


def test_p4_gen_wireshark_no_options(tmpdir):
    tmp_dir = tmpdir.mkdir("tmp")
    original_dir = os.path.abspath(os.curdir)
    base_input = os.path.abspath("../tests/p4_programs/simple_nat.p4")
    base_output = os.path.abspath("../tests/outputs/simple_nat-ipv4.lua")
    exec_path = os.path.abspath("../bin/p4-gen-wireshark")
    os.chdir(str(tmp_dir))
    assert call_p4_gen_wireshark(str(base_input), exec_path=exec_path) is None
    output = os.path.abspath("simple_nat-ipv4.lua")
    assert filecmp.cmp(str(base_output),
                       str(output), shallow=False)
    os.chdir(str(original_dir))


def test_p4_gen_wireshark_given_output_name_and_protocol(tmpdir):
    tmp_dir = tmpdir.mkdir("tmp")
    original_dir = os.path.abspath(os.curdir)
    base_input = os.path.abspath("../tests/p4_programs/heavy_hitter.p4")
    base_output = os.path.abspath("../tests/outputs/heavy_hitter-tcp.lua")
    exec_path = os.path.abspath("../bin/p4-gen-wireshark")
    os.chdir(str(tmp_dir))
    assert call_p4_gen_wireshark(str(base_input) + " -d foo.lua -p tcp",
                                 exec_path=exec_path) is None
    output = os.path.abspath("foo.lua")
    assert filecmp.cmp(str(base_output),
                       str(output), shallow=False)
    os.chdir(str(original_dir))

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

import os
import filecmp
import subprocess


dir_path = os.path.dirname(os.path.realpath(__file__))


def call_p4_gen_wireshark(options, exec_path=None):
    if exec_path is None:
        exec_path = os.path.join(dir_path, os.pardir, "bin/p4-gen-wireshark")
    try:
        subprocess.call([exec_path] + options)
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
    base_input = os.path.join(dir_path, "p4_programs/simple_nat.p4")
    base_output = os.path.join(dir_path, "outputs/simple_nat-ipv4.lua")
    exec_path = os.path.join(dir_path, os.pardir, "bin/p4-gen-wireshark")
    os.chdir(str(tmp_dir))
    assert call_p4_gen_wireshark([base_input], exec_path=exec_path) is None
    output = os.path.join(str(tmp_dir), "simple_nat-ipv4.lua")
    assert filecmp.cmp(base_output, output, shallow=False)
    os.chdir(original_dir)


def test_p4_gen_wireshark_given_output_name_and_protocol(tmpdir):
    tmp_dir = tmpdir.mkdir("tmp")
    base_input = os.path.join(dir_path, "p4_programs/heavy_hitter.p4")
    base_output = os.path.join(dir_path, "outputs/heavy_hitter-tcp.lua")
    exec_path = os.path.join(dir_path, os.pardir, "bin/p4-gen-wireshark")
    output = os.path.join(str(tmp_dir), "foo.lua")
    options = [base_input, "-d", output, "-p", "tcp"]
    assert call_p4_gen_wireshark(options, exec_path=exec_path) is None
    assert filecmp.cmp(base_output, output, shallow=False)

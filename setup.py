#!/usr/bin/env python

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


from setuptools import setup


setup(
    name='p4_gen',
    version='0.1',
    install_requires=['p4_hlir'],
    packages=['p4_gen'],
    package_data={'p4_gen': ['p4_dissector_template.lua']},
    scripts=['bin/p4-gen-wireshark'],
    author='Georgios Nikolaidis',
    author_email='gnikolaidis@barefootnetworks.com',
    description='p4_gen: A P4 to Wireshark dissector generator',
    license='Apache 2.0',
    url='http://www.barefootnetworks.com/',
)

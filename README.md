# P4 Wireshark Dissector Generator
P4 Wireshark dissector generator is a tool that allows P4 programmers to quickly
generate a Wireshark dissector in Lua from the headers defined within a P4 file.

## Requirements

* P4 input file
* P4-HLIR
* Wireshark

## Installation
To install, execute the setup script using:

    sudo python setup.py install

## Generating a dissector
To generate a dissector, run p4-gen-wireshark from your command line. The syntax
is:

    p4-gen-wireshark [-d <destination>] [-p <protocol>] <p4_source>

where:

    -d <destination>
    Destination file. If none given, the destination has the form
    <pwd>/<p4_source>-<protocol>.lua

    -p <protocol>
    Protocol in P4 source file for which to build a dissector. Use instance
    rather than header name (i.e. without a "_t" at the end). If none is given,
    build a dissector for every protocol.

    <p4_source>
    P4 source file.

## Using dissectors
To use your dissector with Wireshark, open a terminal window and type:

    wireshark -X lua_script:<dissector>

where:

    <dissector>
    Is the filename of your generated dissector.

## Running unit tests
You first need to install the `pytest` Python package. You can then run:

    pytest tests/test_p4_gen.py

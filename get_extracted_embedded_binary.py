#!/usr/bin/python3
# Program to extract an ELF binary which is embdedded inside an ELF binary

# Version - 0.1
# Date - 24/Feb/2023

__Author__ = "Rajesh Kumar N"
__version__ = "0.1"

import os
import sys


def calculate_size_of_file(file_contents):
    import lief
    binary = lief.parse(raw=file_contents)

    start_of_section_header = binary.header.section_header_offset

    size_of_section_header = binary.header.section_header_size

    number_of_section_header = binary.header.numberof_sections

    size_of_file = start_of_section_header + (size_of_section_header * number_of_section_header)

    return size_of_file


def calculate_sha256sum(file_contents):
    import hashlib
    return hashlib.sha256(file_contents).hexdigest();


def write_embedded_content_to_file(file_name, embedded_file_content):
    with open(file_name, 'wb') as out_file:
        out_file.write(embedded_file_content)


class ExtractEmbeddedElfBinary:
    def __init__(self, path_to_binary):
        self.binary_path = path_to_binary
        self.matched_offset = []

    def validate_file_size(self):
        with open(self.binary_path, "rb") as file_hdlr:
            file_contents = file_hdlr.read()

        if os.path.getsize(self.binary_path) == calculate_size_of_file(file_contents):
            return True
        else:
            return False

    def get_embedded_elf_start_offsets(self):
        import re
        import yara
        
        with open(self.binary_path, "rb") as file_hdlr:
            file_contents = file_hdlr.read()
            hex_bytes = "7f 45 4c 46"
            search_bytes = bytes.fromhex(hex_bytes)
            
            elf_start_offsets = [m.start() for m in re.finditer(search_bytes, file_contents)]

            for offset in elf_start_offsets:
                if offset != 0:
                    elf_header = 'rule ELF_Header { strings: $a = { 7f 45 4c 46 (01 | 02) (01 | 02) 01 [9] (00 | 01 | 02 | 03 | 04) 00 [2] 01 00 00 00 [16-28] ( 40 | 34)} condition: $a in (' + str(offset) + '..' + str(offset+20) + ') }'                
                    rule = yara.compile(source=elf_header)
                    matches = rule.match(data=file_contents)
                    if matches:
                        self.matched_offset.append(offset)


    def extract_embedded_file(self):
        if not self.matched_offset:
            print("No binary is embedded inside {0}".format(self.binary_path))

        for offset in self.matched_offset:
            with open(self.binary_path, "rb") as file_hdlr:
                file_hdlr.seek(offset)
                remaining_content = file_hdlr.read()
                embedded_file_size = calculate_size_of_file(remaining_content)
                embedded_file_content = remaining_content[0:embedded_file_size]
                file_name = calculate_sha256sum(embedded_file_content)
                write_embedded_content_to_file(file_name, embedded_file_content)
                print("Extracted binary: {0}".format(file_name))


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("{0} <path_to_binary>".format(sys.argv[0]))
        sys.exit(0)

    path_to_binary = sys.argv[1]

    extract_binary = ExtractEmbeddedElfBinary(path_to_binary)
    # print(extract_binary.validate_file_size())
    extract_binary.get_embedded_elf_start_offsets()
    extract_binary.extract_embedded_file()
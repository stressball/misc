import pefile
import os
import sys
import json
import argparse
from Crypto.Cipher import ARC4

class PE_FILE:

    good_sections = [".reloc", ".text", ".data", ".rdata", ".rodata", ".rsrc", ".pdata"]
    sus_section_data = dict()

    def __init__(self, inputf, outputf=None):
        self.analyzef = inputf
        self.target = None
        self.output_file = outputf
    # end of __init__

    def analyze_class_file(self, section_data):
        key = section_data[0:32]
        data_size = section_data[36:40]
        data_size_int = int.from_bytes(data_size, "little")

        print(f"Key: {key.hex()}")
        print(f"Encrypted data size: {data_size_int}")

        data = section_data[40:40+data_size_int]

        cipher = ARC4.new(key)
        decrypted_data = cipher.decrypt(data)
        decrypted_str = decrypted_data.decode().rstrip("\x00")
        config_data = json.loads(decrypted_str)

        if( self.output_file != None ):
            with open(self.output_file, "w") as f:
                f.write(json.dumps(config_data, indent=4))
        else:
            print(f"No output file given.  Throwing away decrypted data")
    # end of def

    def do_stuff(self):
        if( os.path.isfile(self.analyzef) ):
            print(f"File to analyze: {self.analyzef}")
        else:
            print(f"{self.analyzef} not a file.  exiting")
            sys.exit()

        self.target = pefile.PE(self.analyzef)
    
        if( self.target.is_exe() ):
            print(f"{self.analyzef} is EXE")

        self.list_dlls_func()
        self.list_sections()
    # end of def

    def list_sections(self):
        print("Suspicious PE Sections")
        for section in self.target.sections:
            sec_name = section.Name.decode().rstrip("\x00")
            if( sec_name not in self.good_sections ):
                print(f"{sec_name}")
                self.sus_section_data[sec_name] = section.get_data()
                self.analyze_class_file(self.sus_section_data[sec_name])
        # end of for
    # end of def

    def list_dlls_func(self):
        print("Imported DLL and functions list")
        try:
            for item in self.target.DIRECTORY_ENTRY_IMPORT:
                print(f"{item.dll.decode()}")
                for imp in item.imports:
                    print(f"\t{imp.name.decode()}")
            # end of for item
        except Exception as e:
            print(f"Error in list_dlls_func: {e}")
    # end of def
# end of Class

if( __name__ == "__main__" ):
    parser = argparse.ArgumentParser(description="testing")
    parser.add_argument('--file', '-f', type=str, required=True, help='file to analyze')
    parser.add_argument('--output', '-o', type=str, help='write decrypted data to file')
    args = parser.parse_args()

    input_file = PE_FILE(args.file, args.output)
    input_file.do_stuff()
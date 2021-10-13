import os, sys
import pathlib
import pefile
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from xml.etree import ElementTree
from decoding.OoaWrapper import OoaWrapper
 
ORIGIN_LICENSE_AES_KEY = "QTJyLdCC77DcZFfFdmjKCQ=="
ORIGIN_LICENSE_PATH = "C:\\ProgramData\\Electronic Arts\\EA Services\\License"
 
def aes_decrypt(data, key):
    assert len(key) == 16, "AES-128 key size mismatch."
    aes_cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))
    decrypted_data = aes_cipher.decrypt(data)
    return unpad(decrypted_data, 16)
 
def get_decryption_key(content_id):
    for root, dirs, files in os.walk(ORIGIN_LICENSE_PATH):
        for file in files:
            if file == f"{content_id}.dlf" or file == f"{content_id}_cached.dlf":
                license_path = os.path.join(root, file)
                with open(license_path, "r+b") as license_file:
                    license_file.seek(0x41)
                    license_body_enc = license_file.read()
                    license_body_dec = aes_decrypt(license_body_enc, binascii.a2b_base64(ORIGIN_LICENSE_AES_KEY))
                    license_body_xml = ElementTree.fromstring(license_body_dec)
                    decryption_key = binascii.a2b_base64(license_body_xml.find("{http://ea.com/license}CipherKey").text)[:16]
 
                    # Inform if <GameToken> is present (Denuvo giveaway).
                    if license_body_xml.find("{http://ea.com/license}GameToken") is not None:
                        print("INFO: Target executable is protected by Denuvo.")
 
                    return decryption_key
    return None


def parse_ooa_section(pe_file):
    for index, section in enumerate(pe_file.sections):
        section_name = fix_string(section.Name.decode("utf-8"))
        if section_name == ".ooa":
            section_data = pe_file.get_data(section.VirtualAddress, section.SizeOfRawData)
            return OoaWrapper(section_data).OoaData
    return None


def get_encrypted_sections(pe_file, ooa_section):
    encrypted_sections = []
    for index, section in enumerate(pe_file.sections):
        for encrypted_block in ooa_section.enc_blocks:
            if section.VirtualAddress == encrypted_block.virtual_address:
                encrypted_sections.append(section)
    return encrypted_sections


def delete_section(pe_file, section):
    section_alignment = pe_file.OPTIONAL_HEADER.SectionAlignment
    new_last_section = pe_file.sections[-2]

    new_size_of_image = new_last_section.VirtualAddress + new_last_section.Misc_VirtualSize
    b = new_size_of_image % section_alignment
    if b != 0:
        new_size_of_image = new_size_of_image // section_alignment * section_alignment + section_alignment
    
    #Don't need to do checks because we already know that someone added this section + it is always the last section
    pe_file.FILE_HEADER.NumberOfSections -= 1
    pe_file.OPTIONAL_HEADER.SizeOfImage = new_size_of_image

    sectionCount = pe_file.FILE_HEADER.NumberOfSections

    pe_file.sections.pop()

    #4 = signature
    nt_headers = pe_file.DOS_HEADER.e_lfanew + pe_file.FILE_HEADER.sizeof() + pe_file.FILE_HEADER.SizeOfOptionalHeader


    pe_file.set_bytes_at_offset(nt_headers + sectionCount * 0x28, b"\00" * 0x28)

    pe_file.header = pe_file.header[: nt_headers + sectionCount * 0x28] + b"\00" * 0x28 + pe_file.header[nt_headers + sectionCount * 0x28 + 0x28:]


def delete_ooa_section(pe_file):
    for index, section in enumerate(pe_file.sections):
        section_name = fix_string(section.Name.decode("utf-8"))
        if section_name == ".ooa":
            delete_section(pe_file, section)
            return True
    return False


def fix_string(string):
    fixed_string = ''
    for char in string:
        if char == "\0":
            break
        fixed_string += char
    return fixed_string


def decryptSections(pe_file, pe_sections, decryption_key):
    for index, section in enumerate(pe_sections):
        section_data = pe_file.get_data(section.VirtualAddress, section.SizeOfRawData)
        decrypted_section = aes_decrypt(section_data, decryption_key)

        pe_file.set_bytes_at_rva(section.VirtualAddress, bytes(section.SizeOfRawData))
        pe_file.set_bytes_at_rva(section.VirtualAddress, decrypted_section)


def fixHeaders(pe_file, ooa_info):
    pe_oep = ooa_info.address_of_entry_point

    pe_iat = ooa_info.import_address_table_directory_data.virtual_address
    pe_iat_size = ooa_info.import_address_table_directory_data.size

    pe_imports = ooa_info.import_directory_data.virtual_address
    pe_imports_size = ooa_info.import_directory_data.size

    pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]].VirtualAddress = ooa_info.base_relocation_table_directory_data.virtual_address
    pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]].Size = ooa_info.base_relocation_table_directory_data.size

    # Add the OEP and fix the imports directory and table.
    pe_file.OPTIONAL_HEADER.AddressOfEntryPoint = pe_oep if pe_oep else pe_file.OPTIONAL_HEADER.AddressOfEntryPoint
    pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]].VirtualAddress = pe_imports
    pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]].Size = pe_imports_size
 
    # Parse our imports again given the new import directory.
    # NOTE: Don't parse only IMAGE_DIRECTORY_ENTRY_IMPORT as
    # a weird bug happens where generate_checksum will cut off part of the relocations if we don't reparse them.
    pe_file.parse_data_directories()
 
    # Update our IAT directory.
    if pe_iat and pe_iat_size:
        pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]].VirtualAddress = pe_iat
        pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]].Size = pe_iat_size
 
    # Needs some work - eventually switch to another pe library because this one apparently doesn't allow directly editing header data
    #delete_ooa_section(pe_file)

    pe_file.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks = ooa_info.tls_address_of_callbacks + pe_file.OPTIONAL_HEADER.ImageBase

    # Fix TLS Directory - Very important! Some origin stub versions use this. General rule: if it isnt zero, set it
    if ooa_info.first_tls_callback != 0:
        pe_file.set_bytes_at_rva(ooa_info.tls_address_of_callbacks, ooa_info.first_tls_callback.to_bytes(8, byteorder='little', signed = False))


def main():
    pe_path = pathlib.Path(sys.argv[1])

    pe_file = pefile.PE(pe_path)

    ooa_info = parse_ooa_section(pe_file)

    #ideally the first one
    pe_content_id = ooa_info.content_ids.replace('\0', '').rstrip().split(',')[0]
            
    pe_sections = get_encrypted_sections(pe_file, ooa_info)

    # Get the decryption key from our license.
    decryption_key = get_decryption_key(pe_content_id)

    decryptSections(pe_file, pe_sections, decryption_key)
    
    fixHeaders(pe_file, ooa_info)

    # Remove the digital signature.
    #pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].VirtualAddress = 0
    #pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size = 0
 
    # Finalize by aligning sections, and updating the checksum.
    pe_file.merge_modified_section_data()
    #pe_file.OPTIONAL_HEADER.CheckSum = pe_file.generate_checksum()
    pe_file.write(filename=f"{pe_path.stem}.fixed{pe_path.suffix}")

if __name__ == "__main__":
    main()
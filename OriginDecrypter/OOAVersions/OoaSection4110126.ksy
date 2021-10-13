meta:
  id: ooa_section_4110126
  file-extension: ooa_section
seq:
  - id: jmp_asm
    type: jump_instr
  - id: gap
    size: 8
  - id: activation_dll_str
    type: str
    encoding: ascii
    size: 22
  - id: machine_id_version
    type: str
    encoding: ascii
    size: 4
  - id: version_id_sha1_hash
    size: 20
  - id: origin_flag
    type: origin_flags
  - id: content_ids
    encoding: utf-16
    type: str
    size: 0x200
  - id: import_directory
    type: import_descriptor
    repeat: until
    repeat-until: _.characteristics == 0
  - id: import_address_table_directory
    type: image_thunk_data
    repeat: until
    repeat-until: _.function == 0
  - id: original_thunk_directory
    type: image_thunk_data
    repeat: until
    repeat-until: _.function == 0
  - id: gap3
    size: 72
  - id: relocation_directory_max_size
    type: u4le
  - id: new_relocation_directory_size
    type: u4le
  - id: new_relocation_directory
    type: image_base_relocations
    size: new_relocation_directory_size
  - id: gap5
    size: relocation_directory_max_size - new_relocation_directory_size
  - id: has_tls
    type: u4le
  - id: tls_address_of_callbacks
    type: u4le
  - id: first_tls_callback
    type: u8le
#  - id: tls_callback_offsets
#    type: u8le
#    if: true
#    repeat-until: _ == 0
#    repeat: until
#  - id: alignment_gap
#    if: true
#    size: (_io.pos % 0x100 > 0xea) ? (0x1ea -  _io.pos % 0x100) : (0xea - _io.pos % 0x100)
  - id: address_of_entry_point
    type: u4le
  - id: count_of_crypted_sections
    type: u1
  - id: enc_blocks
    type: enc_block_data
    repeat: expr
    repeat-expr: count_of_crypted_sections
  - id: useless_bloat
    size: 10 * 48 - count_of_crypted_sections * 48
  - id: gap7
    size: 8
  - id: unknown_always_1
    type: u2le
  - id: image_base
    type: u8le
  - id: size_of_image
    type: u4le
  - id: import_directory_data
    type: image_data_directory
  - id: base_relocation_table_directory_data
    type: image_data_directory
  - id: import_address_table_directory_data
    type: image_data_directory
  - id:  denuvo_dll_name
    type: str
    encoding: ascii
    size: 16
types:
  jump_instr:
    seq:
      - id: nop
        size: 1
      - id: jmp
        size: 7
  origin_flags:
    seq:
      - id: require_origin
        type: b1le
      - id: encrypt
        type: b1le
      - id: gap
        size: 3
  import_descriptors:
    seq:
      - id: entries
        type: import_descriptor
        repeat: until
        repeat-until: _.characteristics == 0
  image_thunks:
    seq:
      - id: entries
        type: image_thunk_data
        repeat: eos
        
  import_descriptor:
    seq:
      - id: characteristics
        type: u4le
      - id: time_date_stamp
        type: u4le
      - id: forwarder_chain
        type: u4le
      - id: name
        type: u4le
      - id: first_thunk
        type: u4le
  image_thunk_data:
    seq:
      - id: function
        type: u4le
      - id: address_of_data
        type: u4le
  image_import_by_name:
    seq:
      - id: hint
        type: u4le
      - id: name
        type: u4le
  image_data_directory:
    seq:
      - id: virtual_address
        type: u4le
      - id: size
        type: u4le
  image_base_relocations:
    seq:
      - id: image_base_relocation
        type: image_base_relocation
        repeat: eos
  image_base_relocation:
    seq:
      - id: virtual_address
        type: u4le
      - id: size_of_block
        type: u4le
      - id: type_offsets
        type: type_offsets
        size: size_of_block - 8

  type_offsets:
    seq:
      - id: type_offset
        type: u2le
        repeat: eos
  enc_block_data:
    seq:
      - id: virtual_address
        type: u4le
      - id: raw_size
        type: u4le
      - id: virtual_size
        type: u4le
      - id: unknown
        type: u4le
      - id: scuffed_crc32_block
        type: u4le
      - id: unknown1
        type: u4le
      - id: other__scuffed_crc
        type: u4le
      - id: another_gap
        size: 4
      - id: file_offset
        type: u4le
      - id: gap1
        size: 12
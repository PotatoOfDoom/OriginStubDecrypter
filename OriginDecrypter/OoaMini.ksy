meta:
  id: ooa_section
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
  type_offsets:
    seq:
      - id: type_offset
        type: u2le
        repeat: eos

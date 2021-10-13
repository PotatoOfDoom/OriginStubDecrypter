# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if parse_version(kaitaistruct.__version__) < parse_version('0.9'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class OoaSection5021592(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.jmp_asm = OoaSection5021592.JumpInstr(self._io, self, self._root)
        self.gap = self._io.read_bytes(8)
        self.activation_dll_str = (self._io.read_bytes(22)).decode(u"ascii")
        self.machine_id_version = (self._io.read_bytes(4)).decode(u"ascii")
        self.version_id_sha1_hash = self._io.read_bytes(20)
        self.origin_flag = OoaSection5021592.OriginFlags(self._io, self, self._root)
        self.content_ids = (self._io.read_bytes(512)).decode(u"utf-16")
        self.import_directory = []
        i = 0
        while True:
            _ = OoaSection5021592.ImportDescriptor(self._io, self, self._root)
            self.import_directory.append(_)
            if _.characteristics == 0:
                break
            i += 1
        self.import_address_table_directory = []
        i = 0
        while True:
            _ = OoaSection5021592.ImageThunkData(self._io, self, self._root)
            self.import_address_table_directory.append(_)
            if _.function == 0:
                break
            i += 1
        self.original_thunk_directory = []
        i = 0
        while True:
            _ = OoaSection5021592.ImageThunkData(self._io, self, self._root)
            self.original_thunk_directory.append(_)
            if _.function == 0:
                break
            i += 1
        self.gap3 = self._io.read_bytes(72)
        self.relocation_directory_max_size = self._io.read_u4le()
        self.new_relocation_directory_size = self._io.read_u4le()
        self._raw_new_relocation_directory = self._io.read_bytes(self.new_relocation_directory_size)
        _io__raw_new_relocation_directory = KaitaiStream(BytesIO(self._raw_new_relocation_directory))
        self.new_relocation_directory = OoaSection5021592.ImageBaseRelocations(_io__raw_new_relocation_directory, self, self._root)
        self.gap5 = self._io.read_bytes((self.relocation_directory_max_size - self.new_relocation_directory_size))
        self.has_tls = self._io.read_u4le()
        self.tls_address_of_callbacks = self._io.read_u4le()
        self.first_tls_callback = self._io.read_u8le()
        if True:
            self.tls_callback_offsets = []
            i = 0
            while True:
                _ = self._io.read_u8le()
                self.tls_callback_offsets.append(_)
                if _ == 0:
                    break
                i += 1

        if True:
            self.alignment_gap = self._io.read_bytes(((490 - (self._io.pos() % 256)) if (self._io.pos() % 256) > 234 else (234 - (self._io.pos() % 256))))

        self.address_of_entry_point = self._io.read_u4le()
        self.count_of_crypted_sections = self._io.read_u1()
        self.enc_blocks = [None] * (self.count_of_crypted_sections)
        for i in range(self.count_of_crypted_sections):
            self.enc_blocks[i] = OoaSection5021592.EncBlockData(self._io, self, self._root)

        self.useless_bloat = self._io.read_bytes(((10 * 48) - (self.count_of_crypted_sections * 48)))
        self.gap7 = self._io.read_bytes(8)
        self.unknown_always_1 = self._io.read_u1()
        self.image_base = self._io.read_u8le()
        self.size_of_image = self._io.read_u4le()
        self.import_directory_data = OoaSection5021592.ImageDataDirectory(self._io, self, self._root)
        self.base_relocation_table_directory_data = OoaSection5021592.ImageDataDirectory(self._io, self, self._root)
        self.import_address_table_directory_data = OoaSection5021592.ImageDataDirectory(self._io, self, self._root)
        self.denuvo_dll_name = (self._io.read_bytes(16)).decode(u"ascii")

    class OriginFlags(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.require_origin = self._io.read_bits_int_le(1) != 0
            self.encrypt = self._io.read_bits_int_le(1) != 0
            self._io.align_to_byte()
            self.gap = self._io.read_bytes(3)


    class ImportDescriptor(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.characteristics = self._io.read_u4le()
            self.time_date_stamp = self._io.read_u4le()
            self.forwarder_chain = self._io.read_u4le()
            self.name = self._io.read_u4le()
            self.first_thunk = self._io.read_u4le()


    class EncBlockData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.virtual_address = self._io.read_u4le()
            self.raw_size = self._io.read_u4le()
            self.virtual_size = self._io.read_u4le()
            self.unknown = self._io.read_u4le()
            self.scuffed_crc32_block = self._io.read_u4le()
            self.unknown1 = self._io.read_u4le()
            self.other__scuffed_crc = self._io.read_u4le()
            self.another_gap = self._io.read_bytes(4)
            self.file_offset = self._io.read_u4le()
            self.gap1 = self._io.read_bytes(12)


    class JumpInstr(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.nop = self._io.read_bytes(1)
            self.jmp = self._io.read_bytes(7)


    class ImageDataDirectory(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.virtual_address = self._io.read_u4le()
            self.size = self._io.read_u4le()


    class ImageThunkData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.function = self._io.read_u4le()
            self.address_of_data = self._io.read_u4le()


    class TypeOffsets(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.type_offset = []
            i = 0
            while not self._io.is_eof():
                self.type_offset.append(self._io.read_u2le())
                i += 1



    class ImageBaseRelocation(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.virtual_address = self._io.read_u4le()
            self.size_of_block = self._io.read_u4le()
            self._raw_type_offsets = self._io.read_bytes((self.size_of_block - 8))
            _io__raw_type_offsets = KaitaiStream(BytesIO(self._raw_type_offsets))
            self.type_offsets = OoaSection5021592.TypeOffsets(_io__raw_type_offsets, self, self._root)


    class ImageBaseRelocations(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.image_base_relocation = []
            i = 0
            while not self._io.is_eof():
                self.image_base_relocation.append(OoaSection5021592.ImageBaseRelocation(self._io, self, self._root))
                i += 1



    class ImageThunks(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.entries = []
            i = 0
            while not self._io.is_eof():
                self.entries.append(OoaSection5021592.ImageThunkData(self._io, self, self._root))
                i += 1



    class ImageImportByName(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.hint = self._io.read_u4le()
            self.name = self._io.read_u4le()


    class ImportDescriptors(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.entries = []
            i = 0
            while True:
                _ = OoaSection5021592.ImportDescriptor(self._io, self, self._root)
                self.entries.append(_)
                if _.characteristics == 0:
                    break
                i += 1




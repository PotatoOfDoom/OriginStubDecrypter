# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if parse_version(kaitaistruct.__version__) < parse_version('0.9'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class OoaSectionMini(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.jmp_asm = OoaSectionMini.JumpInstr(self._io, self, self._root)
        self.gap = self._io.read_bytes(8)
        self.activation_dll_str = (self._io.read_bytes(22)).decode(u"ascii")
        self.machine_id_version = (self._io.read_bytes(4)).decode(u"ascii")
        self.version_id_sha1_hash = self._io.read_bytes(20)
        self.origin_flag = OoaSectionMini.OriginFlags(self._io, self, self._root)
        self.content_ids = (self._io.read_bytes(512)).decode(u"utf-16")

    class JumpInstr(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.nop = self._io.read_bytes(1)
            self.jmp = self._io.read_bytes(7)


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

#small version of the ooa section that only contains enough info to parse things till the version hash. then select the right structure for the version hash.
from OriginDecrypter.OoaMini import OoaSectionMini
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO

from Crypto.Hash import SHA1

import importlib

class OoaWrapper:
    def __init__(self, ooaData):
        self.rawData = ooaData
        ooaMini = OoaSectionMini(KaitaiStream(BytesIO(self.rawData)))

        versions = {
            SHA1.new(b'5.02.15.92').digest(): 'OoaSection5021592',
            SHA1.new(b'5.02.04.66').digest(): 'OoaSection5020162',
            SHA1.new(b'5.02.01.62').digest(): 'OoaSection5020162', #seems like content is the same - no need to create another file definition
            SHA1.new(b'4.11.04.26').digest(): 'OoaSection4110126',
            SHA1.new(b'4.11.02.11').digest(): 'OoaSection4110126',
            SHA1.new(b'4.11.01.297').digest(): 'OoaSection4110126',
        }

        self.version = versions[ooaMini.version_id_sha1_hash]

        if self.version is None:
            raise Exception("Unknown OOA version" + " Hash: " + hex(ooaMini.version_id_sha1_hash))

        module = importlib.import_module('OriginDecrypter.OOAVersions.' + self.version)
        realest_class = getattr(module, self.version)

        self.OoaData = realest_class(KaitaiStream(BytesIO(self.rawData)))

    def getVersion(self):
        return self.version
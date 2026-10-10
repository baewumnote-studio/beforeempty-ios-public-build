import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from cryptography.exceptions import InvalidTag
import sealed_io as sealed

class SealedTests(unittest.TestCase):
    def test_roundtrip_and_unique_nonce(self):
        key=os.urandom(32); data=b'private fixture'*100
        a=sealed.seal(data,key); b=sealed.seal(data,key)
        self.assertEqual(sealed.unseal(a,key),data)
        self.assertNotEqual(a,b)
        self.assertNotIn(data,a)
    def test_tamper_and_wrong_key_rejected(self):
        key=os.urandom(32); data=sealed.seal(b'private',key)
        for damaged,k in [(data[:-1]+bytes([data[-1]^1]),key),(data,os.urandom(32))]:
            with self.assertRaises(InvalidTag): sealed.unseal(damaged,k)
    def test_archive_traversal_rejected_before_writing(self):
        for name in ['../secret','/secret','C:/secret','folder\\secret']:
            data=io.BytesIO()
            info=zipfile.ZipInfo('fixture')
            info.filename=name  # Preserve hostile raw separators on Windows too.
            with zipfile.ZipFile(data,'w') as z: z.writestr(info,b'x')
            with tempfile.TemporaryDirectory() as folder:
                with self.assertRaises(ValueError): sealed.extract_zip(data.getvalue(),folder)
    def test_symlink_rejected(self):
        data=io.BytesIO(); info=zipfile.ZipInfo('link'); info.external_attr=0o120777<<16
        with zipfile.ZipFile(data,'w') as z: z.writestr(info,b'../secret')
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError): sealed.extract_zip(data.getvalue(),folder)
    def test_regular_archive_roundtrip(self):
        data=io.BytesIO()
        with zipfile.ZipFile(data,'w') as z: z.writestr('app/source.txt',b'fixture')
        with tempfile.TemporaryDirectory() as folder:
            sealed.extract_zip(data.getvalue(),folder)
            self.assertEqual((Path(folder)/'app/source.txt').read_bytes(),b'fixture')

if __name__=='__main__': unittest.main()

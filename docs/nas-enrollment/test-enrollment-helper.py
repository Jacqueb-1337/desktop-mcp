import base64
import importlib.util
import unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location("helper",Path(__file__).with_name("enrollment-helper.py"))
helper=importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
class Validation(unittest.TestCase):
    def test_valid_and_invalid_requests(self):
        identity="DM1-"+"12"*32
        peer=base64.b64encode(bytes(range(1,33))).decode()
        request=f"{identity} {peer}\n".encode()
        self.assertEqual(helper.parse(request)[:2],(identity,peer))
        for bad in [request+b"extra",request.replace(b"DM1-",b"DM2-"),request.replace(b" ",b";"),request[:-1],
                    f"{identity} {'A'*43}=\n".encode(),f"{identity} {'B'*43}=\n".encode()]:
            with self.assertRaises(ValueError):
                helper.parse(bad)
if __name__=="__main__":
    unittest.main()

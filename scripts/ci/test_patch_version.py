"""patch_version.py reply parsing (no network)."""
import struct
import unittest

import patch_version as pv


def reply(root, second="https://patch.poecdn.com/"):
    data = bytes([0x02]) + bytes(32)
    for text in (root, second):
        data += struct.pack(">H", len(text)) + text.encode("utf-16-le")
    return data


class PatchVersionTests(unittest.TestCase):
    def test_parses_the_versioned_web_root(self):
        root, digest = pv.parse_reply(reply("https://patch.poecdn.com/3.29.3.3/"))
        self.assertEqual(root, "https://patch.poecdn.com/3.29.3.3/")
        self.assertEqual(digest, "00" * 32)
        self.assertEqual(pv.version_of(root), "3.29.3.3")

    def test_refuses_unexpected_replies_and_roots(self):
        with self.assertRaises(ValueError):
            pv.parse_reply(b"\x03" + bytes(40))
        for root in ["http://patch.poecdn.com/3.29.3.3/", "https://example.com/3.29.3.3/",
                     "https://patch.poecdn.com/latest/", "https://patch.poecdn.com/3.29.3.3/x/",
                     "https://patch.poecdn.com/3.29.3.3"]:
            with self.assertRaises(ValueError, msg=root):
                pv.version_of(root)

    def test_reads_a_reply_split_across_packets(self):
        data = reply("https://patch.poecdn.com/3.29.3.3/")

        class Socket:
            chunks = [data[:10], data[10:40], data[40:]]

            def recv(self, size):
                return self.chunks.pop(0) if self.chunks else b""
        self.assertEqual(pv.read_reply(Socket()), data)


if __name__ == "__main__":
    unittest.main()

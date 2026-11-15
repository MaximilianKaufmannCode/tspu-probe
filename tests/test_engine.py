import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest

from engine_loader import load_engine

E = load_engine()


def sni_from_client_hello(body):
    """Extract the server_name from a reassembled ClientHello handshake message."""
    p = 4 + 2 + 32
    p += 1 + body[p]
    p += 2 + int.from_bytes(body[p:p + 2], "big")
    p += 1 + body[p]
    end = p + 2 + int.from_bytes(body[p:p + 2], "big")
    p += 2
    while p + 4 <= end:
        typ = int.from_bytes(body[p:p + 2], "big")
        ln = int.from_bytes(body[p + 2:p + 4], "big")
        if typ == 0:
            nl = int.from_bytes(body[p + 7:p + 9], "big")
            return body[p + 9:p + 9 + nl].decode()
        p += 4 + ln
    return None


def read_records(conn, first=None):
    """Read TLS records until a whole ClientHello is buffered; return (first_chunk, handshake_body)."""
    conn.settimeout(3)
    raw = first if first is not None else conn.recv(65535)
    first_chunk = raw
    body = b""
    while True:
        while len(raw) >= 5:
            ln = int.from_bytes(raw[3:5], "big")
            if len(raw) < 5 + ln:
                break
            body += raw[5:5 + ln]
            raw = raw[5 + ln:]
        if len(body) >= 4 and len(body) >= 4 + int.from_bytes(body[1:4], "big"):
            return first_chunk, body
        more = conn.recv(65535)
        if not more:
            return first_chunk, body
        raw += more


class FakeTLS(threading.Thread):
    """Loopback 'TLS server': records the SNI it reassembles; optionally plays a DPI box
    that sends RST when the blocked name is visible inside the FIRST received chunk."""

    def __init__(self, block=None):
        super().__init__(daemon=True)
        self.block = block.encode() if block else None
        self.seen = []
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(16)
        self.srv.settimeout(0.2)
        self.port = self.srv.getsockname()[1]
        self.stop = False

    def run(self):
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                first = c.recv(65535)
                if self.block and self.block in first:
                    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    c.close()
                    continue
                _, body = read_records(c, first)
                self.seen.append(sni_from_client_hello(body) if len(body) > 40 else None)
                c.sendall(b"\x16\x03\x03\x00\x05hello")
            except OSError:
                pass
            finally:
                try:
                    c.close()
                except OSError:
                    pass

    def close(self):
        self.stop = True
        self.srv.close()


class VoteTests(unittest.TestCase):
    def test_strict_majority(self):
        self.assertEqual(E.vote(["OK", "OK", "RST"]), "OK(2/3)")
        self.assertEqual(E.vote(["RST", "RST", "RST"]), "RST(3/3)")

    def test_tie_is_mixed_not_first_seen(self):
        self.assertEqual(E.vote(["OK", "TIMEOUT", "RST"]), "MIXED(OK/TIMEOUT/RST)")
        self.assertEqual(E.vote(["OK", "RST"]), "MIXED(OK/RST)")

    def test_empty(self):
        self.assertEqual(E.vote([]), "ERR(0/0)")


class VerdictTests(unittest.TestCase):
    def run_verdict(self, lines):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        try:
            d = E.verdict_data(f.name)
        finally:
            os.unlink(f.name)
        return d, E.verdict_text(d)

    @staticmethod
    def sni(dom, normal, s1="OK(3/3)", s4="OK(3/3)", ss="OK(3/3)", tr="OK(3/3)"):
        return "sni %s (1.2.3.4): normal=%s split1=%s split4=%s splitSNI=%s TLSrec=%s" % (dom, normal, s1, s4, ss, tr)

    def test_no_blocking_never_claims_bypass(self):
        d, text = self.run_verdict([self.sni("a.example", "OK(3/3)"), self.sni("b.example", "OK(3/3)")])
        self.assertEqual(d["blocked"], [])
        self.assertIn("n/a", text)
        self.assertNotIn("bypassed", text)

    def test_bypass_counts_only_on_blocked_domains(self):
        bad = "RST(3/3)"
        d, text = self.run_verdict([
            self.sni("ok.example", "OK(3/3)"),
            self.sni("blk.example", bad, bad, bad, "OK(3/3)", "OK(2/3)"),
        ])
        self.assertEqual(d["blocked"], ["blk.example"])
        self.assertEqual(d["bypass"]["splitSNI"], ["blk.example"])
        self.assertEqual(d["bypass"]["TLSrec"], ["blk.example"])
        self.assertEqual(d["bypass"]["split1"], [])
        self.assertIn("splitSNI: 1/1", text)

    def test_unblocked_domains_do_not_fake_a_bypass(self):
        # regression: the old verdict grepped every `sni` line, so OK on unblocked hosts looked like a bypass
        bad = "RST(3/3)"
        d, text = self.run_verdict([
            self.sni("ok.example", "OK(3/3)"),
            self.sni("blk.example", bad, bad, bad, bad, bad),
        ])
        self.assertEqual(d["blocked"], ["blk.example"])
        self.assertTrue(all(not v for v in d["bypass"].values()))
        self.assertIn("none-observed", text)

    def test_mixed_is_inconclusive_and_never_a_bypass(self):
        d, _ = self.run_verdict([
            self.sni("blk.example", "RST(3/3)", ss="MIXED(OK/RST/TIMEOUT)"),
            self.sni("flaky.example", "MIXED(OK/RST/TIMEOUT)"),
            self.sni("err.example", "ERR(3/3)"),
        ])
        self.assertEqual(d["blocked"], ["blk.example"])
        self.assertEqual(d["bypass"]["splitSNI"], [])
        self.assertEqual(sorted(d["inconclusive"]), ["err.example", "flaky.example"])

    def test_strategy_that_breaks_unblocked_domain_is_flagged(self):
        d, text = self.run_verdict([self.sni("ok.example", "OK(3/3)", s1="RST(3/3)")])
        self.assertEqual(d["breaks_unblocked"]["split1"], ["ok.example"])
        self.assertIn("warning: split1", text)

    def test_no_ip_counted(self):
        d, _ = self.run_verdict(["sni gone.example: NO-IP", self.sni("a.example", "OK(3/3)")])
        self.assertEqual(d["no_ip"], 1)

    def test_hop_located_and_not_located(self):
        d, text = self.run_verdict(['  hop rutracker (1.2.3.4): {"dpi_hop": 5, "trace": [[1, "TO"]], "note": ""}'])
        self.assertEqual(d["dpi_hop"], 5)
        self.assertIn("TTL >= 5", text)
        d, text = self.run_verdict(['  hop rutracker (1.2.3.4): {"dpi_hop": null, "trace": [], "note": ""}'])
        self.assertIsNone(d["dpi_hop"])
        self.assertIn("not located", text)
        d, text = self.run_verdict([])
        self.assertIn("not measured", text)

    def test_dns_transport_lines(self):
        d, text = self.run_verdict([
            '  dns-transport @8.8.8.8: {"udp": ["193.232.230.48"], "tcp": ["172.253.1.2"], "tcp_status": "OK", "verdict": "udp-diverted"}',
            '  dns-transport @1.1.1.1: {"udp": [], "tcp": [], "tcp_status": "TIMEOUT", "verdict": "inconclusive"}',
        ])
        self.assertEqual(d["dns_transport"], {"8.8.8.8": "udp-diverted", "1.1.1.1": "inconclusive"})
        self.assertIn("dns @8.8.8.8: UDP/53 answered from 193.232.*", text)
        self.assertIn("dns @1.1.1.1: UDP/53 vs TCP/53 inconclusive", text)
        self.assertEqual(self.run_verdict([])[0]["dns_transport"], {})


class TransportVerdictTests(unittest.TestCase):
    def test_udp_to_nsdi_tcp_clean(self):
        self.assertEqual(E.transport_verdict(["193.232.230.48"], ["172.253.1.2"]), "udp-diverted")

    def test_both_nsdi_is_not_udp_only(self):
        self.assertEqual(E.transport_verdict(["193.232.230.48"], ["193.232.230.48"]), "same")

    def test_differs_and_missing(self):
        self.assertEqual(E.transport_verdict(["172.253.1.2"], ["74.125.1.1"]), "differs")
        self.assertEqual(E.transport_verdict([], ["74.125.1.1"]), "inconclusive")
        self.assertEqual(E.transport_verdict(["193.232.230.48"], []), "inconclusive")


class FragTests(unittest.TestCase):
    def test_frag_records_reassemble(self):
        ch = E.build_ch("example.org")
        self.assertTrue(ch)
        for off in (1, 7, 40, len(ch) - 6):
            recs = E.frag_records(ch, off)
            self.assertEqual(len(recs), 2)
            body = b""
            for r in recs:
                self.assertEqual(int.from_bytes(r[3:5], "big"), len(r) - 5)
                body += r[5:]
            self.assertEqual(body, ch[5:])

    def test_client_hello_carries_sni(self):
        self.assertEqual(sni_from_client_hello(E.build_ch("example.org")[5:]), "example.org")


class TlsProbeTests(unittest.TestCase):
    def test_all_modes_deliver_the_same_sni(self):
        srv = FakeTLS()
        srv.start()
        try:
            for mode in ("none", "s1", "s4", "sni", "trec"):
                r = E.tls_probe("127.0.0.1", "good.example", mode, port=srv.port, delay=0.05)
                self.assertEqual(r["status"], "OK", mode)
        finally:
            srv.close()
        self.assertEqual(srv.seen, ["good.example"] * 5)

    def test_dpi_sim_blocks_normal_but_not_split_sni(self):
        srv = FakeTLS(block="blocked.example")
        srv.start()
        try:
            res = {m: E.tls_probe("127.0.0.1", "blocked.example", m, port=srv.port, delay=0.1)["status"]
                   for m in ("none", "s1", "s4", "sni", "trec")}
            vote = E.tls_vote("127.0.0.1", "blocked.example", "none", tries=3, port=srv.port)
        finally:
            srv.close()
        self.assertEqual(res["none"], "RST")
        self.assertEqual(res["sni"], "OK")
        self.assertEqual(res["trec"], "OK")
        self.assertEqual(vote, "RST(3/3)")

    def test_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertEqual(E.tls_probe("127.0.0.1", "x.example", "none", port=port)["status"], "REFUSED")

    def test_hop_finds_rst_at_ttl_1_on_loopback(self):
        srv = FakeTLS(block="blocked.example")
        srv.start()
        try:
            r = E.hop("127.0.0.1", "blocked.example", maxttl=3, port=srv.port)
        finally:
            srv.close()
        self.assertEqual(r["dpi_hop"], 1)


def dns_answer(query, ips, cname=None):
    """Build a response for `query`; names are compressed with a pointer to the question."""
    ans = b""
    n = 0
    if cname:
        enc = b"".join(bytes([len(p)]) + p.encode() for p in cname.split(".")) + b"\0"
        ans += b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, len(enc)) + enc
        n += 1
    for ip in ips:
        ans += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
        n += 1
    return query[:2] + b"\x81\x80" + b"\x00\x01" + n.to_bytes(2, "big") + b"\0\0\0\0" + query[12:] + ans


class DnsTests(unittest.TestCase):
    def test_parse_plain_a(self):
        q = E._dns_query("a.example")
        self.assertEqual(E._parse_a(dns_answer(q, ["1.2.3.4", "5.6.7.8"])), ["1.2.3.4", "5.6.7.8"])

    def test_parse_cname_then_a(self):
        q = E._dns_query("a.example")
        self.assertEqual(E._parse_a(dns_answer(q, ["9.9.9.9"], cname="cdn.example")), ["9.9.9.9"])

    def test_parse_nxdomain_and_garbage(self):
        q = E._dns_query("a.example")
        self.assertEqual(E._parse_a(dns_answer(q, [])), [])
        self.assertEqual(E._parse_a(b"\x00\x01\x02"), [])
        self.assertEqual(E._parse_a(b""), [])

    def udp_server(self, replies_for):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        srv.settimeout(3)

        def run():
            try:
                q, addr = srv.recvfrom(512)
                for ips in replies_for:
                    srv.sendto(dns_answer(q, ips), addr)
                    time.sleep(0.05)
            except OSError:
                pass
            finally:
                srv.close()

        threading.Thread(target=run, daemon=True).start()
        return srv.getsockname()[1]

    def test_dnsmulti_flags_injection(self):
        port = self.udp_server([["10.0.0.1"], ["1.2.3.4"]])
        r = E.dnsmulti("127.0.0.1", "a.example", window=1.0, port=port)
        self.assertEqual(r["count"], 2)
        self.assertTrue(r["injected"])

    def test_dnsmulti_single_answer_is_clean(self):
        port = self.udp_server([["1.2.3.4"]])
        r = E.dnsmulti("127.0.0.1", "a.example", window=1.0, port=port)
        self.assertEqual(r["count"], 1)
        self.assertFalse(r["injected"])

    def test_dns_tcp_length_prefix_in_separate_segment(self):
        # regression: a single recv() returned only the 2-byte prefix, so ips was always []
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(3)

        def run():
            try:
                c, _ = srv.accept()
                n = int.from_bytes(c.recv(2), "big")
                q = b""
                while len(q) < n:
                    q += c.recv(n - len(q))
                resp = dns_answer(q, ["1.2.3.4"])
                c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                c.sendall(len(resp).to_bytes(2, "big"))
                time.sleep(0.1)
                c.sendall(resp)
                c.close()
            except OSError:
                pass
            finally:
                srv.close()

        threading.Thread(target=run, daemon=True).start()
        r = E.dns_tcp("127.0.0.1", "a.example", port=srv.getsockname()[1])
        self.assertEqual(r, {"status": "OK", "ips": ["1.2.3.4"]})

    def test_dns_tcp_eof(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(3)

        def run():
            try:
                c, _ = srv.accept()
                c.recv(512)
                c.close()
            except OSError:
                pass
            finally:
                srv.close()

        threading.Thread(target=run, daemon=True).start()
        self.assertEqual(E.dns_tcp("127.0.0.1", "a.example", port=srv.getsockname()[1])["status"], "EOF")


class StunTests(unittest.TestCase):
    def test_stun_ok_on_custom_port(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        srv.settimeout(3)

        def run():
            try:
                d, addr = srv.recvfrom(512)
                srv.sendto(b"\x01\x01\x00\x00" + d[4:20], addr)
            except OSError:
                pass
            finally:
                srv.close()

        threading.Thread(target=run, daemon=True).start()
        r = E.stun("127.0.0.1", srv.getsockname()[1])
        self.assertEqual(r["status"], "OK")


if __name__ == "__main__":
    unittest.main()

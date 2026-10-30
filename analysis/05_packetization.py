#!/usr/bin/env python3
"""Packetization summaries (Figure 2) and TLS record byte breakdown (Table 6).

Source: data/raw/openssl-3.5.0/packetization/<scenario>_mtu<MTU>/analysis.json.
Each capture contains the connections produced by a 5-iteration s_client run
against s_server (loopback-equivalent veth pair, no netem impairment). The
captures contain the TLS 1.3 handshake, two NewSessionTicket messages and the
close_notify alert; no HTTP request or response is exchanged.

Qualifying connections: payload in both directions and more than 100 bytes of
server payload (excludes the empty and the alert-only connection).

Record labels are inferred from the TLS 1.3 message order and record lengths
(ServerHello and ChangeCipherSpec are plaintext; the rest are encrypted
records whose length includes the 1-byte inner content type and 16-byte tag).
Record lengths exclude the 5-byte record header.

The copies of these summaries under other host/release directories are checked
for byte identity: they duplicate the same OpenSSL 3.5.0 captures.
"""
import hashlib

from common import RAW, load, rel, write_csv

SCENARIOS = {
    "baseline": ("X25519", "RSA-2048 (RSA-PSS)"),
    "hybrid-kem": ("X25519MLKEM768", "RSA-2048 (RSA-PSS)"),
    "pqc-kem": ("ML-KEM-768", "RSA-2048 (RSA-PSS)"),
    "pqc-cert": ("X25519", "ML-DSA-65"),
    "full-pqc": ("ML-KEM-768", "ML-DSA-65"),
}
SERVER_LABELS = ["ServerHello", "ChangeCipherSpec", "EncryptedExtensions", "Certificate",
                 "CertificateVerify", "Finished", "NewSessionTicket", "NewSessionTicket",
                 "Alert (close_notify)"]
CLIENT_LABELS = ["ClientHello", "ChangeCipherSpec", "Finished", "Alert (close_notify)"]
FLIGHT = set(range(6))  # ServerHello .. Finished
BASE = RAW / "openssl-3.5.0" / "packetization"


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    seg_rows, rec_rows, dup_rows = [], [], []
    for sc, (kex, auth) in SCENARIOS.items():
        for mtu in (1500, 1400, 1280):
            d = BASE / f"{sc}_mtu{mtu}"
            a, m = load(d / "analysis.json"), load(d / "metadata.json")
            assert "3.5.0" in m["environment"]["openssl_version"]
            conns = a["connections"]
            q = [c for c in conns if c["client_to_server"]["total_payload_bytes"] > 0
                 and c["server_to_client"]["total_payload_bytes"] > 100]
            s2c = [c["server_to_client"]["segments_with_payload"] for c in q]
            c2s = [c["client_to_server"]["segments_with_payload"] for c in q]
            srec = [[(r["content_type"], r["length"]) for r in c["server_to_client"]["tls_records"]] for c in q]
            crec = [[(r["content_type"], r["length"]) for r in c["client_to_server"]["tls_records"]] for c in q]
            assert all(x == srec[0] for x in srec) and all(x == crec[0] for x in crec)
            assert len(srec[0]) == len(SERVER_LABELS) and len(crec[0]) == len(CLIENT_LABELS)
            assert all(c.get("retransmissions", 0) == 0 for c in q)  # field is not populated by the parser
            flight = sum(L + 5 for i, (_, L) in enumerate(srec[0]) if i in FLIGHT)
            total = sum(L + 5 for _, L in srec[0])
            mss = a["aggregated"]["server_mss"]
            seg_rows.append([sc, kex, auth, mtu, mss, m["capture_info"]["cert_der_size_bytes"], len(conns), len(q),
                             sum(s2c) / len(s2c), min(s2c), max(s2c), sum(c2s) / len(c2s),
                             flight, -(-flight // mss), total, rel(d / "analysis.json")])
            if mtu == 1500:
                for i, (ct, L) in enumerate(srec[0]):
                    rec_rows.append([sc, kex, auth, "server->client", SERVER_LABELS[i], ct, L])
                for i, (ct, L) in enumerate(crec[0]):
                    rec_rows.append([sc, kex, auth, "client->server", CLIENT_LABELS[i], ct, L])
            # Other copies in the archive. The lab-server directories hold byte-identical copies of
            # the laptop-directory files; the openssl-3.4.1 directories hold a second capture session
            # that was also produced with the OpenSSL 3.5.0 binary.
            second = RAW / "openssl-3.4.1" / "packetization" / f"{sc}_mtu{mtu}" / "analysis.json"
            b = load(second)
            qb = [c for c in b["connections"] if c["client_to_server"]["total_payload_bytes"] > 0
                  and c["server_to_client"]["total_payload_bytes"] > 100]
            same_counts = (sorted(c["server_to_client"]["segments_with_payload"] for c in qb) == sorted(s2c)
                           and all([(r["content_type"], r["length"]) for r in c["server_to_client"]["tls_records"]]
                                   == srec[0] for c in qb))
            dup_rows.append([rel(second), rel(d / "analysis.json"), "second capture session",
                             b["environment"]["openssl_version"], sha(second) == sha(d / "analysis.json"),
                             same_counts])
            for host_dir, src in (("openssl-3.5.0", d / "analysis.json"), ("openssl-3.4.1", second)):
                copy = RAW / "lab-server" / host_dir / "packetization" / f"{sc}_mtu{mtu}" / "analysis.json"
                dup_rows.append([rel(copy), rel(src), "lab-server copy", "", sha(copy) == sha(src), ""])
    write_csv("figure2_packetization_segments.csv",
              ["scenario", "key_establishment", "authentication", "mtu", "server_mss", "cert_der_bytes",
               "connections_detected", "qualifying_connections", "mean_s2c_payload_segments",
               "min_s2c", "max_s2c", "mean_c2s_payload_segments", "server_flight_bytes_SH_to_Finished",
               "min_segments_for_flight_at_mss", "server_bytes_incl_tickets_and_close", "file"], seg_rows)
    write_csv("table6_tls_record_bytes_mtu1500.csv",
              ["scenario", "key_establishment", "authentication", "direction", "message_inferred",
               "record_content_type", "record_length_bytes"], rec_rows)
    write_csv("packetization_copies.csv", ["file", "compared_with", "relation", "declared_openssl", "byte_identical", "same_qualifying_segment_counts_and_records"], dup_rows)
    print(f"{'scenario':11} {'MTU':>4}  S2C  C2S  flight_B  min_seg  conns/qual")
    for r in seg_rows:
        print(f"{r[0]:11} {r[3]:4}  {r[8]:4.1f} {r[11]:4.1f}  {r[12]:8}  {r[13]:7}  {r[6]}/{r[7]}")
    print("server records @1500:")
    for sc in SCENARIOS:
        print(" ", sc, [(r[4][:12], r[6]) for r in rec_rows if r[0] == sc and r[3] == "server->client"])
        print("   client", [(r[4][:12], r[6]) for r in rec_rows if r[0] == sc and r[3] == "client->server"])
    lab = [r for r in dup_rows if r[2] == "lab-server copy"]
    sec = [r for r in dup_rows if r[2] == "second capture session"]
    print(f"lab-server copies: {len(lab)}, byte-identical: {all(r[4] for r in lab)}")
    print(f"second capture sessions: {len(sec)}, all OpenSSL 3.5.0: {all('3.5.0' in r[3] for r in sec)}, same counts/records: {sum(bool(r[5]) for r in sec)}/{len(sec)}")


if __name__ == "__main__":
    main()

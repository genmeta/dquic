"""Regenerate test credentials with Python cryptography; tests use the saved files."""

from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


ROOT = Path(__file__).parent
START = datetime(2020, 1, 1, tzinfo=timezone.utc)
END = datetime(2040, 1, 1, tzinfo=timezone.utc)


def issue(name, key, issuer=None, issuer_key=None, ca=False, extensions=()):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (x509.CertificateBuilder().subject_name(subject)
               .issuer_name(issuer.subject if issuer else subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(START).not_valid_after(END)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    for value, critical in extensions:
        builder = builder.add_extension(value, critical=critical)
    return builder.sign(issuer_key or key, hashes.SHA256())


def save(name, certificates):
    (ROOT / name).write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certificates))


keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(16)]
cas = [issue("long-chain root", keys[0], ca=True)]
for i in range(1, 16):
    cas.append(issue(f"long-chain CA {i}", keys[i], cas[-1], keys[i - 1], ca=True))
save("ca.pem", [cas[0]])
leaf_key = ec.generate_private_key(ec.SECP256R1())
(ROOT / "leaf.key").write_bytes(leaf_key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
extensions = [
    (x509.SubjectAlternativeName([x509.DNSName("localhost")]), False),
    (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False),
]
for length in (9, 16):
    issuer = cas[length - 1]
    leaf = issue("localhost", leaf_key, issuer, keys[length - 1], extensions=extensions)
    save(f"chain-{length}.pem", [leaf, *reversed(cas[1:length])])
    response = (ocsp.OCSPResponseBuilder().add_response(
        leaf, issuer, hashes.SHA1(), ocsp.OCSPCertStatus.GOOD, START, END, None, None)
        .responder_id(ocsp.OCSPResponderEncoding.HASH, issuer)
        .sign(keys[length - 1], hashes.SHA256()))
    (ROOT / f"chain-{length}.ocsp").write_bytes(response.public_bytes(serialization.Encoding.DER))

restricted = issue("long-chain CA 4", keys[4], cas[3], keys[3], ca=True, extensions=[
    (x509.NameConstraints(permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None), True),
])
save("restricted-ca.pem", [restricted])

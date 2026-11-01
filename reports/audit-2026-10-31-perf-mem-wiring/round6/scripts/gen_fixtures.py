#!/usr/bin/env python3
"""生成 TLS/REALITY 审计夹具（证书 + REALITY 密钥对）。

产出（同目录 fixtures/）：
  ca.pem / ca.key                自签 CA（测试信任根）
  leaf.pem / leaf.key            CA 签发的 test.example 叶证书（有效）
  expired.pem / expired.key      CA 签发的 test.example 叶证书（已过期）
  selfsigned.pem / selfsigned.key 自签 test.example（不在任何信任根内）
  reality_priv.b64 / reality_pub.b64  X25519 密钥对（base64url no-pad）
"""
import base64
import datetime
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.x509.oid import NameOID

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "fixtures"
OUT.mkdir(parents=True, exist_ok=True)

NOW = datetime.datetime.now(datetime.timezone.utc)


def write_key(path, key):
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def write_cert(path, cert):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def mk_name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def mk_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(mk_name("Audit Test CA"))
        .issuer_name(mk_name("Audit Test CA"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    write_key(OUT / "ca.key", key)
    write_cert(OUT / "ca.pem", cert)
    return key, cert


def mk_leaf(ca_key, ca_cert, name, cn, san, not_before, not_after):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(mk_name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    write_key(OUT / f"{name}.key", key)
    write_cert(OUT / f"{name}.pem", cert)
    return cert


def mk_selfsigned():
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(mk_name("test.example"))
        .issuer_name(mk_name("test.example"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("test.example")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    write_key(OUT / "selfsigned.key", key)
    write_cert(OUT / "selfsigned.pem", cert)
    return cert


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def main():
    ca_key, ca_cert = mk_ca()
    leaf = mk_leaf(
        ca_key,
        ca_cert,
        "leaf",
        "test.example",
        "test.example",
        NOW - datetime.timedelta(days=1),
        NOW + datetime.timedelta(days=30),
    )
    expired = mk_leaf(
        ca_key,
        ca_cert,
        "expired",
        "test.example",
        "test.example",
        NOW - datetime.timedelta(days=40),
        NOW - datetime.timedelta(days=10),
    )
    selfsigned = mk_selfsigned()

    priv = x25519.X25519PrivateKey.generate()
    (OUT / "reality_priv.b64").write_text(
        b64url(priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    )
    (OUT / "reality_pub.b64").write_text(
        b64url(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    )

    # 叶证书/过期证书的 SHA-256（pin 用）
    for name, cert in [("leaf", leaf), ("expired", expired), ("selfsigned", selfsigned)]:
        der = cert.public_bytes(serialization.Encoding.DER)
        import hashlib

        (OUT / f"{name}.sha256").write_text(hashlib.sha256(der).hexdigest())

    print("fixtures written to", OUT)
    print("reality privateKey =", (OUT / "reality_priv.b64").read_text())
    print("leaf sha256 =", (OUT / "leaf.sha256").read_text())


if __name__ == "__main__":
    sys.exit(main())

"""
core/pki.py
-----------
Infraestructura de clave publica (PKI).

Resuelve el problema que ECDH/firmas dejan abierto: ¿como sabe Bob que la
llave publica que recibio realmente es de Alice y no de Eve? Una Autoridad
Certificadora (CA) firma un "certificado" que liga una identidad con una
llave publica. Bob confia en el certificado SOLO si fue firmado por una
CA que el ya considera confiable (su "almacen de confianza").
"""
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from .common import OperationResult, Measure


def build_ca(common_name: str = "CA de Laboratorio Confiable"):
    """Crea una autoridad certificadora raiz autofirmada (para fines didacticos)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256()))
    return private_key, cert


def issue_certificate(ca_private_key, ca_cert, subject_name: str, subject_public_key) -> OperationResult:
    with Measure() as m:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
        cert = (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(ca_cert.subject)
                .public_key(subject_public_key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=90))
                .sign(ca_private_key, hashes.SHA256()))
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    return OperationResult(
        mechanism="Emision de certificado X.509",
        inputs={"sujeto": subject_name, "CA_emisora": ca_cert.subject.rfc4514_string()},
        components={"certificado_X509_DER": cert_der, "llave_privada_de_la_CA": "***oculta, solo la CA la tiene***"},
        secret_info={"llave_privada_de_la_CA": "***oculta***"},
        public_info={"certificado": cert_der},
        outputs={"certificado": cert},
        property_provided="Autenticacion de la IDENTIDAD de quien posee la llave publica dentro del "
                           "certificado, respaldada por la firma de la CA.",
        resources=m.as_dict(output_size=len(cert_der)),
        usage_conditions=[
            "Un certificado solo es tan confiable como la CA que lo firmo y la verificacion de la "
            "cadena hasta una CA raiz en el almacen de confianza del verificador.",
            "Debe revisarse vigencia (not_valid_before/after) y, en sistemas reales, revocacion (CRL/OCSP).",
        ],
    )


def verify_certificate(cert, trusted_ca_certs: list) -> OperationResult:
    """Verifica que 'cert' fue firmado por ALGUNA de las CAs en trusted_ca_certs.
    Simulacion simplificada (un solo nivel, sin cadena intermedia) para fines didacticos.
    """
    accepted = False
    matching_ca = None
    note = ""
    with Measure() as m:
        for ca_cert in trusted_ca_certs:
            try:
                ca_cert.public_key().verify(
                    cert.signature, cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),
                )
                if cert.issuer == ca_cert.subject:
                    accepted = True
                    matching_ca = ca_cert.subject.rfc4514_string()
                    break
            except Exception:
                continue
        now = datetime.datetime.now(datetime.timezone.utc)
        if accepted and not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            accepted = False
            note = "La firma de la CA es valida, pero el certificado esta fuera de su periodo de vigencia."
        if not accepted and not note:
            note = ("La firma del certificado NO corresponde a ninguna CA del almacen de confianza "
                     "de Bob. El certificado pudo ser emitido por una CA desconocida/no confiable "
                     "(p. ej. una CA que Eve controla). Bob debe RECHAZARLO.")

    return OperationResult(
        mechanism="Verificacion de certificado X.509 (PKI)",
        inputs={"sujeto_del_certificado": cert.subject.rfc4514_string(),
                 "emisor_declarado": cert.issuer.rfc4514_string()},
        components={"CAs_confiables_de_Bob": [c.subject.rfc4514_string() for c in trusted_ca_certs]},
        secret_info={},
        public_info={"certificado": "(ver 'inputs')"},
        property_provided="Autenticacion de identidad, condicionada a la confianza en el emisor.",
        resources=m.as_dict(),
        accepted=accepted,
        notes=note if note else f"Verificado contra: {matching_ca}",
    )

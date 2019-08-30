import os
import subprocess
import platform
import tempfile
import logging

from lxml import etree

log = logging.getLogger(__name__)

class SignatureVerifierError(Exception):
    """There was a problem validating the response"""
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return '%s: %s' % (self.__doc__, self._msg)


class SignatureVerifier(object):
    def __init__(self, idp_cert_filename, private_key_file):
        print("Creating sign verifier")
        self.idp_cert_filename = idp_cert_filename
        self.private_key_file = private_key_file

    def verify_and_decrypt(self, document, signature):
        return self.verify(document,
                           signature,
                           self.idp_cert_filename,
                           self.private_key_file)

    @staticmethod
    def _get_xmlsec_bin():
        xmlsec_bin = 'xmlsec1'
        if platform.system() == 'Windows':
            xmlsec_bin = 'xmlsec.exe'

        return xmlsec_bin


    def verify(
        self,
        document,
        signature,
        idp_cert_filename,
        private_key_file,
        _etree=None,
        _tempfile=None,
        _subprocess=None,
        _os=None,
        ):
        """
        Verify that signature contained in the samlp:Response is valid when checked against the provided signature.
        Return True if valid, otherwise False
        Arguments:
        document -- lxml.etree.XML object containing the samlp:Response
        signature -- The fingerprint to check the samlp:Response against
        """
        if _etree is None:
            _etree = etree
        if _tempfile is None:
            _tempfile = tempfile
        if _subprocess is None:
            _subprocess = subprocess
        if _os is None:
            _os = os

        xmlsec_bin = self._get_xmlsec_bin()

        verified = False
        decrypted = False
        with _tempfile.NamedTemporaryFile(delete=False) as xml_fp:
            self.write_xml_to_file(document, xml_fp)

            verified = self.verify_xml(xml_fp.name, xmlsec_bin, idp_cert_filename)
            if verified:
                decrypted = self.decrypt_xml(xml_fp.name, xmlsec_bin, private_key_file)

        return verified, decrypted

    @staticmethod
    def _parse_stderr(proc):
        output = proc.stderr.read()
        for line in output.split('\n'):
            line = line.strip()
            if line == 'OK':
                return True
            elif line == 'FAIL':
                [log.info('XMLSec: %s' % line)
                 for line in output.split('\n')
                 if line
                 ]
                return False

        # If neither success nor failure
        print(output)
        if proc.returncode is not 0:
            msg = 'XMLSec returned error code %s. Please check your certficate.'
            raise SignatureVerifierError(msg % proc.returncode)

        # Should not happen
        raise SignatureVerifierError(
            'XMLSec exited with code 0 but did not return OK when verifying the SAML response.'
            )

    @staticmethod
    def verify_xml(xml_filename, xmlsec_bin, idp_cert_filename):
        # We cannot use xmlsec python bindings to verify here because
        # that would require a call to libxml2.xmlAddID. The libxml2 python
        # bindings do not yet provide this function.
        # http://www.aleksey.com/xmlsec/faq.html Section 3.2
        cmds = [
            xmlsec_bin,
            '--verify',
            '--pubkey-cert-pem',
            idp_cert_filename,
            '--id-attr',
            'ID',
            xml_filename,
            ]

        print("COMMANDS", cmds)
        proc = subprocess.Popen(
            cmds,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            )
        proc.wait()
        return SignatureVerifier._parse_stderr(proc)


    @staticmethod
    def decrypt_xml(xml_filename, xmlsec_bin, private_key_file):
        cmds = [
            xmlsec_bin,
            '--decrypt',
            '--privkey-pem',
            private_key_file,
            xml_filename
            ]

        print("COMMANDS", cmds)
        proc = subprocess.Popen(
            cmds,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            )
        out, err = proc.communicate()
        return out

    @staticmethod
    def write_xml_to_file(document, xml_fp):
        doc_str = etree.tostring(document)
        xml_fp.write('<?xml version="1.0" encoding="utf-8"?>')
        xml_fp.write("<!DOCTYPE test [<!ATTLIST samlp:Response ID ID #IMPLIED>]>")
        xml_fp.write(doc_str)
        print("XML:")
        print(doc_str)
        xml_fp.seek(0)

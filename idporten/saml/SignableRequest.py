import zlib
import base64
import uuid
import urllib.request, urllib.parse, urllib.error
from urllib.parse import urlencode
import tempfile
import subprocess as subp

from datetime import datetime
from lxml import etree
from lxml.builder import ElementMaker


def sign_request(urlencoded_request, private_key_file):
    with tempfile.NamedTemporaryFile(delete=False) as output_file:
        output_file.write(urlencoded_request.encode("utf-8"))
        output_file.seek(0)

        cmds = [
            "openssl",
            "sha1",
            "-sign",
            private_key_file,
            output_file.name ]

        proc = subp.Popen(
            cmds,
            stdout=subp.PIPE,
            stderr=subp.PIPE)
        out, err = proc.communicate()
        print(err)

    out = base64.b64encode(out)
    return urllib.parse.urlencode([("Signature", out),])


class SignableRequest(object):
    def __init__(self):
        self.document = None
        self.target_url = None

    def get_signed_url(self, private_key_file, _zlib=None, _base64=None, _urllib=None):
        if _zlib is None:
            _zlib = zlib
        if _base64 is None:
            _base64 = base64
        if _urllib is None:
            _urllib = urllib

        authn_request_string = etree.tostring(self.document, xml_declaration=True, encoding='UTF-8')


        compressed_request = _zlib.compress(authn_request_string)
        # Strip the first 2 bytes (header) and the last 4 bytes (checksum) to get the raw deflate
        deflated_request = compressed_request[2:-4]
        encoded_request = _base64.b64encode(deflated_request)
        sig_alg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
        urlencoded_request = _urllib.urlencode(
            [('SAMLRequest', encoded_request),
             ('SigAlg', sig_alg)],)

        signature = sign_request(urlencoded_request, private_key_file)

        return '{url}?{query}&{Signature}'.format(
            url=self.target_url,
            query=urlencoded_request,
            Signature=signature
            )

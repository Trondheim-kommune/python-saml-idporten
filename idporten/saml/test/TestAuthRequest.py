import fudge

from datetime import datetime
from nose.tools import eq_ as eq
from lxml import etree
from xml.dom import minidom
import tempfile
from idporten.saml import AuthRequest

class TestAuthnRequest(object):
    def setUp(self):
        fudge.clear_expectations()

    @fudge.with_fakes
    def test_constructor_creates_expected_document(self):
        fake_uuid_func = fudge.Fake('uuid', callable=True)
        fake_uuid_func.with_arg_count(0)
        fake_uuid = fudge.Fake('foo_uuid')
        fake_uuid.has_attr(hex='hex_uuid')
        fake_uuid = fake_uuid_func.returns(fake_uuid)

        def fake_clock():
            return datetime(2011, 7, 9, 19, 24, 52, 325405)

        expected_xml = """<?xml version=\'1.0\' encoding=\'UTF-8\'?>\n<saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="2011-07-09T19:24:52.875Z" Destination="http://foo.idp.bar" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0" IsPassive="False" AssertionConsumerServiceURL="http://foo.bar/consume" ID="hex_uuid"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">foo_issuer</saml2:Issuer><saml2p:NameIDPolicy AllowCreate="true" SPNameQualifier="foo_issuer" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/><saml2p:RequestedAuthnContext Comparison="minimum"><saml2:AuthnContextClassRef xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2p:RequestedAuthnContext></saml2p:AuthnRequest>"""

        req = AuthRequest(
            _clock=fake_clock,
            _uuid=fake_uuid_func,
            assertion_consumer_service_url='http://foo.bar/consume',
            issuer='foo_issuer',
            name_identifier_format=('urn:oasis:names:tc:SAML:1.1:nameid-format:'
                                    + 'emailAddress'
                                    ),
            idp_sso_target_url='http://foo.idp.bar',
            private_key_file="/private/key_file.txt"
            )


        reparsed = minidom.parseString(etree.tostring(req.document))
        parsed_expected = minidom.parseString(expected_xml)

        eq(reparsed.toprettyxml(), parsed_expected.toprettyxml())




    @fudge.with_fakes
    def test_sign_created_request(self):

        expected_xml = """<?xml version=\'1.0\' encoding=\'UTF-8\'?>\n<saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="2011-07-09T19:24:52.875Z" Destination="http://foo.idp.bar" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0" IsPassive="False" AssertionConsumerServiceURL="http://foo.bar/consume" ID="hex_uuid"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">foo_issuer</saml2:Issuer><saml2p:NameIDPolicy AllowCreate="true" SPNameQualifier="foo_issuer" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/><saml2p:RequestedAuthnContext Comparison="minimum"><saml2:AuthnContextClassRef xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2p:RequestedAuthnContext></saml2p:AuthnRequest>"""
        fake_zlib = fudge.Fake('zlib')
        fake_zlib.remember_order()
        fake_compress = fake_zlib.expects('compress')
        fake_compress.with_args(expected_xml)
        fake_compress.returns('HDfoo_compressedCHCK')

        fake_base64 = fudge.Fake('base64')
        fake_base64.remember_order()
        fake_encode = fake_base64.expects('b64encode')
        fake_encode.with_args('foo_compressed')
        fake_encode.returns('foo_encoded')

        fake_urllib = fudge.Fake('urllib')
        fake_urllib.remember_order()
        fake_urlencode = fake_urllib.expects('parse.urlencode')
        fake_urlencode.with_args(
            [('SAMLRequest', 'foo_encoded'),
             ('SigAlg', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1')]
            )
        fake_urlencode.returns('foo_urlencoded')




        fake_uuid_func = fudge.Fake('uuid', callable=True)
        fake_uuid_func.with_arg_count(0)
        fake_uuid = fudge.Fake('foo_uuid')
        fake_uuid.has_attr(hex='hex_uuid')
        fake_uuid = fake_uuid_func.returns(fake_uuid)

        def fake_clock():
            return datetime(2011, 7, 9, 19, 24, 52, 325405)

        req = AuthRequest(_clock=fake_clock,
                          _uuid=fake_uuid_func,
                          assertion_consumer_service_url='http://foo.bar/consume',
                          issuer='foo_issuer',
                          name_identifier_format=('urn:oasis:names:tc:SAML:1.1:nameid-format:'
                                                  + 'emailAddress'
                                                  ),
                          idp_sso_target_url='http://foo.idp.bar',
                          private_key_file="/private/key_file.txt"
                          )


        with tempfile.NamedTemporaryFile(delete=False) as private_key_file:
            private_key = """
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAMKaEPkdWp024qmWSLGcoyxLodJkm23uNtgJ2XnED9ZlxJyM6mfv
VEPTuetpJuxsAeiWxaKf7KL6EYnEuy0gwV8CAwEAAQJAPBWrxe79Smtm4qvHOCe/
7e5QQZDUuMWDY4LvBfy2UyDAwvc7wSDzLnPjlAho2HgtlRMc4wKzH4P/Iea8RhUx
2QIhAO8TEO02afKrRN7LUlOLOOzBjOF5C3xFiHTfa6ONeBBlAiEA0GD8yIV0K+YF
dkHUmPHUVgaA07oNAStrOj0+leLrlHMCIQCwAlBu46Wio9bjU7s7iH8TRveqM8xx
5Fsu+CGt2oQvRQIhAJ5M/9xpnb53qTCUhCiIlpGfsSCnl5eK35PH0RLW57bHAiAC
ke+DV3hRFd9DgRJNuhEEn94jmsL9rjAnToX/1pFt9A==
-----END RSA PRIVATE KEY-----"""


            private_key_file.write(private_key.encode('UTF-8'))
            private_key_file.seek(0)

            signed_url = req.get_signed_url(private_key_file.name,
                                            _zlib=fake_zlib,
                                            _base64=fake_base64,
                                            _urllib=fake_urllib)
            eq(signed_url, 'http://foo.idp.bar?foo_urlencoded&Signature=owpCXH6cNB%2BLqOAkKKnG4Gz4vNRXbV2G%2Fcnue8SPw4FkNTILInX5Mv7Fma9%2FVjCXiLqRW732cN7GIXBaLbc6hA%3D%3D')

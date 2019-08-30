import fudge

from datetime import datetime
from nose.tools import eq_ as eq

from idporten.saml import LogoutRequest

class TestLogoutRequest(object):
    def setUp(self):
        fudge.clear_expectations()

    @fudge.with_fakes
    def test_create(self):
        fake_uuid_func = fudge.Fake('uuid', callable=True)
        fake_uuid_func.with_arg_count(0)
        fake_uuid = fudge.Fake('foo_uuid')
        fake_uuid.has_attr(hex='hex_uuid')
        fake_uuid = fake_uuid_func.returns(fake_uuid)

        def fake_clock():
            return datetime(2013, 9, 23, 15, 55, 43)

        logout_target_url = "https://example.com/logout_destination"
        issuer = "the_issuer"
        name_id = "the_name_id"
        session_index = "the_session_index"

        expected_xml = """<?xml version="1.0\" encoding="UTF-8"?><saml2p:LogoutRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://example.com/logout_destination" ID="hex_uuid" IssueInstant="2013-09-23T15:55:43.000Z" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">the_issuer</saml2:Issuer><saml2:NameID xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">the_name_id</saml2:NameID><saml2p:SessionIndex>the_session_index</saml2p:SessionIndex></saml2p:LogoutRequest>"""

        logout_request = LogoutRequest(
            _clock=fake_clock,
            _uuid=fake_uuid_func,
            logout_target_url=logout_target_url,
            issuer=issuer,
            name_id=name_id,
            session_index=session_index)

        from xml.dom import minidom
        reparsed = minidom.parseString(logout_request.raw_xml)
        parsed_expected = minidom.parseString(expected_xml)

        print(reparsed.toprettyxml())
        print(parsed_expected.toprettyxml())

        eq(reparsed.toprettyxml(), parsed_expected.toprettyxml())

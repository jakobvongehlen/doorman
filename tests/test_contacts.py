"""The contacts plugin (CardDAV, read-only) against a real Radicale server, its vCard parser, and the owner
app's contact list for "Trust a contact" (GET /owner/contacts)."""

from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from doorman.api.owner import create_owner_app
from doorman.plugins.contacts.plugin import Plugin, parse_vcards, same_number
from conftest import Agent, make_engine

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "doorman" / "plugins" / "contacts"

MKCOL = ('<d:mkcol xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav"><d:set><d:prop><d:resourcetype>'
         '<d:collection/><c:addressbook/></d:resourcetype><d:displayname>{name}</d:displayname></d:prop></d:set>'
         '</d:mkcol>')


def vcard(uid, fn, *lines):
    return "\r\n".join(["BEGIN:VCARD", "VERSION:3.0", f"UID:{uid}", f"FN:{fn}", *lines, "END:VCARD"]) + "\r\n"


def make_book(dav, slug, name, cards):
    """An address book in the user's home on Radicale, filled with `cards` (vCard texts)."""
    with httpx.Client(auth=(dav.user, "x")) as client:
        assert client.request("MKCOL", f"{dav.url}{dav.user}/{slug}/",
                              content=MKCOL.format(name=name).encode()).status_code == 201
        for i, card in enumerate(cards):
            assert client.put(f"{dav.url}{dav.user}/{slug}/{i}.vcf", content=card.encode(),
                              headers={"Content-Type": "text/vcard"}).status_code == 201


LENA = vcard("lena-1", "Léna Bakker", "N:Bakker;Léna;;;", "EMAIL;TYPE=INTERNET,HOME:lena@example.org",
             "EMAIL;TYPE=WORK;TYPE=pref:l.bakker@uni.example", "TEL;TYPE=CELL:+31 6 12345678",
             "ORG:Universiteit Utrecht;Informatica", "NOTE:Group mate\\, project 7\\nlikes tea", "BDAY:1999-04-02")
TOM = vcard("tom-2", "Tom Jansen", "N:Jansen;Tom;;;", "EMAIL:tom.jansen@mail.example", "TEL:0612345000")
PLUMBER = vcard("plumber-3", "Loodgieter Snel", "TEL;TYPE=WORK:030 123 4567", "ORG:Snel BV")
FAMILY = [vcard("mum-4", "Ingrid de Vries", "EMAIL:ingrid@mail.example", "BDAY:--0611")]


@pytest.fixture
def dav(radicale_server):
    """A user of its own on the session's Radicale (conftest.py) with two address books."""
    dav = radicale_server.new_user()
    make_book(dav, "contacts", "Contacts", [LENA, TOM, PLUMBER])
    make_book(dav, "family", "Family", FAMILY)
    return dav


def setup(tmp_path, dav, _engine=None, **config):
    engine = make_engine(tmp_path, **(_engine or {}), plugins={"contacts": {"enabled": True, "config": {
        "url": dav.url, "allow_http": True, **config}}})
    engine.vault.set("contacts", "username", dav.user)
    engine.vault.set("contacts", "password", "x")
    return engine, Agent(engine)


def names(found):
    return [c["name"] for c in found["contacts"]]


pytestmark = pytest.mark.integration


# reads against Radicale


def test_books_lists_every_address_book(tmp_path, dav):
    _, agent = setup(tmp_path, dav)
    assert sorted(agent.read("contacts.books"), key=lambda b: b["name"]) == [
        {"name": "Contacts", "used": True}, {"name": "Family", "used": True}]


def test_search_matches_name_email_phone_and_organisation(tmp_path, dav):
    _, agent = setup(tmp_path, dav)
    assert names(agent.read("contacts.search", {"query": "lena"})) == ["Léna Bakker"]  # accents ignored
    assert names(agent.read("contacts.search", {"query": "uni.example"})) == ["Léna Bakker"]
    assert names(agent.read("contacts.search", {"query": "informatica utrecht"})) == ["Léna Bakker"]
    assert names(agent.read("contacts.search", {"query": "06 1234 5678"})) == ["Léna Bakker"]  # +31 6 ...
    assert names(agent.read("contacts.search", {"query": "snel"})) == ["Loodgieter Snel"]
    assert names(agent.read("contacts.search", {"query": "nobody"})) == []
    found = agent.read("contacts.search", {"query": "lena"})["contacts"][0]
    assert found["emails"][0] == {"address": "l.bakker@uni.example", "type": "work"}  # preferred first
    assert found["organisation"] == "Universiteit Utrecht / Informatica" and found["book"] == "Contacts"
    assert found["ref"] == "contacts:lena-1" and "note" not in found  # the note only with get


def test_search_without_query_lists_everyone_by_name_and_limits(tmp_path, dav):
    _, agent = setup(tmp_path, dav)
    everyone = agent.read("contacts.search", {})
    assert names(everyone) == ["Ingrid de Vries", "Léna Bakker", "Loodgieter Snel", "Tom Jansen"]
    assert everyone["more"] is False
    assert names(agent.read("contacts.search", {"with_email": True})) == [
        "Ingrid de Vries", "Léna Bakker", "Tom Jansen"]
    two = agent.read("contacts.search", {"limit": 2})
    assert len(two["contacts"]) == 2 and two["more"] is True


def test_get_returns_the_whole_card(tmp_path, dav):
    _, agent = setup(tmp_path, dav)
    lena = agent.read("contacts.get", {"id": "lena-1"})
    assert lena["first"] == "Léna" and lena["last"] == "Bakker"
    assert lena["note"] == "Group mate, project 7\nlikes tea" and lena["birthday"] == "1999-04-02"
    assert agent.read("contacts.get", {"id": "mum-4"})["birthday"] == "--06-11"
    with pytest.raises(Exception, match="no contact with id"):
        agent.read("contacts.get", {"id": "nobody"})


def test_books_setting_narrows_and_changes_on_the_server_show_up(tmp_path, dav):
    _, agent = setup(tmp_path, dav, books=["Family"])
    assert names(agent.read("contacts.search", {})) == ["Ingrid de Vries"]
    assert {b["name"]: b["used"] for b in agent.read("contacts.books")} == {"Contacts": False, "Family": True}
    with httpx.Client(auth=(dav.user, "x")) as client:  # a new card: the book's ctag moves
        client.put(f"{dav.url}{dav.user}/family/9.vcf", content=vcard("dad-9", "Henk de Vries").encode(),
                   headers={"Content-Type": "text/vcard"})
    assert names(agent.read("contacts.search", {})) == ["Henk de Vries", "Ingrid de Vries"]


def test_reads_are_owner_data_and_nothing_can_be_written(tmp_path, dav):
    engine, agent = setup(tmp_path, dav)
    agent.read("contacts.search", {"query": "tom"})
    session = engine.db.one("SELECT read_third_party FROM sessions WHERE id=?", (agent.session["id"],))
    assert not session["read_third_party"]  # trust: owner, so the session stays clean
    plugin = next(p for p in engine.registry.list() if p["name"] == "contacts")
    assert plugin["tools"] == []


def test_an_agent_may_set_one_up_switched_off_and_narrow_its_books(tmp_path, dav):
    engine, agent = setup(tmp_path, dav)
    out = engine.setup.call(agent.session, agent.key, "doorman.install", {
        "type": "contacts", "name": "work_contacts", "settings": {"url": "https://cloud.example.com/remote.php/dav/"}})
    assert out["result"]["enabled"] is False  # the owner adds the login and switches it on
    engine.setup.call(agent.session, agent.key, "doorman.configure", {"plugin": "work_contacts",
                                                                     "set": {"books": ["Contacts"]}})
    with pytest.raises(Exception, match="url"):  # the server is the owner's to choose
        engine.setup.call(agent.session, agent.key, "doorman.configure", {"plugin": "work_contacts",
                                                                         "set": {"url": "https://evil.example/"}})


def test_check_reports_named_books_the_server_lacks_and_a_plain_http_address(tmp_path, dav):
    engine, _ = setup(tmp_path, dav, books=["Contacts", "Work"])
    assert engine.registry.instance("contacts").check() == "not on the server: Work"
    engine, _ = setup(tmp_path / "plain", dav)
    engine.registry.instance("contacts").config["allow_http"] = False
    assert "isn't https" in engine.registry.instance("contacts").check()


# shared books (Nextcloud) are never read


NEXTCLOUD_HOME = """<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:cs="http://calendarserver.org/ns/"
    xmlns:card="urn:ietf:params:xml:ns:carddav">
 <d:response><d:href>/remote.php/dav/addressbooks/users/robin/</d:href>
  <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>
 <d:response><d:href>/remote.php/dav/addressbooks/users/robin/contacts/</d:href>
  <d:propstat><d:prop><d:resourcetype><d:collection/><card:addressbook/></d:resourcetype>
   <d:displayname>Contacts</d:displayname><cs:getctag>3</cs:getctag>
   <oc:owner-principal>principals/users/robin</oc:owner-principal></d:prop></d:propstat></d:response>
 <d:response><d:href>/remote.php/dav/addressbooks/users/robin/team_shared_by_alice/</d:href>
  <d:propstat><d:prop><d:resourcetype><d:collection/><card:addressbook/></d:resourcetype>
   <d:displayname>Team</d:displayname><oc:owner-principal>principals/users/alice</oc:owner-principal>
  </d:prop></d:propstat></d:response>
 <d:response><d:href>/remote.php/dav/addressbooks/users/robin/z-server-generated--system/</d:href>
  <d:propstat><d:prop><d:resourcetype><d:collection/><card:addressbook/></d:resourcetype>
   <d:displayname>Accounts</d:displayname><oc:owner-principal>principals/system/system</oc:owner-principal>
  </d:prop></d:propstat></d:response>
</d:multistatus>"""


class FakeNextcloud(Plugin):
    """The plugin with the server's answers canned: Nextcloud's home with a shared and the system book."""

    def request(self, method, url, body, depth):
        self.asked.append((method, url))
        if method == "REPORT":
            if "contacts" not in url:
                raise AssertionError(f"read a book that isn't the owner's: {url}")
            return ElementTree.fromstring("<d:multistatus xmlns:d='DAV:'/>")
        return ElementTree.fromstring(NEXTCLOUD_HOME)

    def home(self):
        self._principal = "/remote.php/dav/principals/users/robin/"
        return "https://cloud.example.com/remote.php/dav/addressbooks/users/robin/"


def nextcloud(**config):
    ctx = SimpleNamespace(instance="contacts", config={"url": "https://cloud.example.com/remote.php/dav/", **config},
                          credentials={})
    plugin = FakeNextcloud(ctx, yaml.safe_load((PLUGIN_DIR / "manifest.yaml").read_text()))
    plugin.asked = []
    return plugin


def test_books_shared_with_the_owner_are_listed_but_never_read():
    plugin = nextcloud()
    assert plugin.read_books({}) == [{"name": "Contacts", "used": True},
                                     {"name": "Team", "used": False, "shared_by": "alice"},
                                     {"name": "Accounts", "used": False, "shared_by": "system"}]
    plugin.read_search({})
    assert [u for m, u in plugin.asked if m == "REPORT"] == [
        "https://cloud.example.com/remote.php/dav/addressbooks/users/robin/contacts/"]
    named = nextcloud(books=["Team", "Contacts"])
    named.read_search({})  # naming a shared book doesn't make it read
    assert named.check() == "shared with you, so never read: Team"


# the vCard parser


def test_parser_reads_folded_lines_groups_and_vcard_21():
    text = ("BEGIN:VCARD\r\nVERSION:2.1\r\nN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:M=C3=BCller;J=C3=BCrgen;;;\r\n"
            "item1.EMAIL;INTERNET;WORK:j.mueller@example.com\r\nTEL;CELL;PREF:+49 170 1234567\r\n"
            "NOTE:a long note that goes on\r\n  over two lines\r\nPHOTO;ENCODING=b:AAAA\r\n"
            "BDAY;X-APPLE-OMIT-YEAR=1604:1604-12-24\r\nEND:VCARD\r\n"
            "BEGIN:VCARD\r\nVERSION:4.0\r\nEMAIL;TYPE=\"home,pref\":mailto:a@b.example\r\n"
            "TEL;VALUE=uri:tel:+31-30-1234567\r\nEND:VCARD\r\n")
    first, second = parse_vcards(text)
    assert first["name"] == "Jürgen Müller" and first["last"] == "Müller"  # no FN: from N
    assert first["emails"] == [{"address": "j.mueller@example.com", "type": "work"}]
    assert first["phones"] == [{"number": "+49 170 1234567", "type": "cell"}]
    assert first["note"] == "a long note that goes on over two lines" and first["birthday"] == "--12-24"
    assert second["name"] == "a@b.example" and second["emails"] == [{"address": "a@b.example", "type": "home"}]
    assert second["phones"] == [{"number": "+31-30-1234567", "type": ""}]


# the owner app's list for "Trust a contact"


def test_owner_contacts_lists_people_with_addresses_and_marks_trusted_ones(tmp_path, dav):
    engine, _ = setup(tmp_path, dav, _engine={"dev_owner_token": "owner-test"})
    engine.db.exec("INSERT INTO trust(kind, value, label, created) VALUES('email', 'tom.jansen@mail.example', "
                   "'Tom', '2026-11-07')")
    client = TestClient(create_owner_app(engine), headers={"Authorization": "Bearer owner-test"})
    assert TestClient(create_owner_app(engine)).get("/owner/contacts").status_code == 401  # the owner's only
    body = client.get("/owner/contacts", params={"q": "jansen"}).json()
    assert body["contacts"] == [{"name": "Tom Jansen", "organisation": "", "source": "contacts",
                                 "ref": "contacts:tom-2",
                                 "emails": [{"address": "tom.jansen@mail.example", "type": "", "trusted": True}]}]
    everyone = client.get("/owner/contacts").json()
    assert [c["name"] for c in everyone["contacts"]] == ["Ingrid de Vries", "Léna Bakker", "Tom Jansen"]  # with email
    assert everyone["sources"] == {"contacts": {"count": 3}} and everyone["more"] is False


# people in the owner's own books count as theirs in the recipient check (known_recipients)


def with_notes(tmp_path, dav, **engine_config):
    engine = make_engine(tmp_path, **engine_config, plugins={
        "notes": {"enabled": True},
        "contacts": {"enabled": True, "config": {"url": dav.url, "allow_http": True}}})
    engine.vault.set("contacts", "username", dav.user)
    engine.vault.set("contacts", "password", "x")
    agent = Agent(engine)
    return engine, agent, agent.call("notes.create", {"title": "Gym"})["result"]["id"]


def test_a_send_to_someone_in_the_owners_contacts_has_no_warning(tmp_path, dav):
    engine, agent, note_id = with_notes(tmp_path, dav)
    out = agent.call("notes.send_copy", {"id": note_id, "to": "L.Bakker@uni.example"})
    assert out["status"] == "waiting_approval" and out["warnings"] == []  # still asks, without "new recipient"
    entry = engine.approvals.get(out["approval_id"])["entries"][0]
    assert entry["untrusted_destinations"] == []
    assert entry["known_destinations"] == [{"kind": "email", "value": "l.bakker@uni.example",
                                            "source": "in your contacts (Léna Bakker)"}]
    stranger = agent.call("notes.send_copy", {"id": note_id, "to": "x@evil.example"})
    assert any("new recipient" in w for w in stranger["warnings"])


def test_with_contacts_off_the_warning_comes_back(tmp_path, dav):
    _, agent, note_id = with_notes(tmp_path, dav, trust={"contacts": False})
    out = agent.call("notes.send_copy", {"id": note_id, "to": "lena@example.org"})
    assert any("new recipient" in w for w in out["warnings"])


def test_numbers_match_a_whatsapp_chat_in_any_format(tmp_path, dav):
    engine, _ = setup(tmp_path, dav)
    found = engine.registry.instance("contacts").known_recipients([
        ["chat", "31612345678@s.whatsapp.net"],   # Léna: +31 6 12345678
        ["chat", "31612345000@s.whatsapp.net"],   # Tom: 0612345000, national
        ["chat", "31301234567@s.whatsapp.net"],   # the plumber: 030 123 4567
        ["phone", "+31612345678"],
        ["chat", "4912345678@s.whatsapp.net"],    # nobody
        ["chat", "120363025@g.us"],               # a group has no number
        ["iban", "NL91ABNA0417164300"]])
    assert {k: v["name"] for k, v in found.items()} == {
        "31612345678@s.whatsapp.net": "Léna Bakker", "31612345000@s.whatsapp.net": "Tom Jansen",
        "31301234567@s.whatsapp.net": "Loodgieter Snel", "+31612345678": "Léna Bakker"}


def test_same_number():
    assert same_number("31612345678", "+31 6 1234 5678") and same_number("31612345678", "0031 6 12345678")
    assert same_number("31612345678", "06 1234 5678") and same_number("4917012345678", "0170 12345678")
    assert not same_number("31612345678", "+49 6 1234 5678")      # another country's code, written out
    assert not same_number("31612345678", "1234 5678")            # no leading 0: not a national number
    assert not same_number("31612345678", "0 5678")               # too short to say
    assert not same_number("99931612345678", "06 1234 5678")      # more than a country code in front


SHARED_CARDS = {"/contacts/": LENA, "/team_shared_by_alice/": vcard("m-1", "Mallory", "EMAIL:mallory@evil.example"),
                "/z-server-generated--system/": vcard("s-1", "Sam", "EMAIL:sam@evil.example")}


class NextcloudWithCards(FakeNextcloud):
    """Every book has a card, so a shared book that were read would make its people known."""

    def request(self, method, url, body, depth):
        self.asked.append((method, url))
        if method == "REPORT":
            card = next(c for slug, c in SHARED_CARDS.items() if slug in url)
            return ElementTree.fromstring(
                "<d:multistatus xmlns:d='DAV:' xmlns:card='urn:ietf:params:xml:ns:carddav'><d:response>"
                f"<d:href>{url}1.vcf</d:href><d:propstat><d:prop><card:address-data>{card}</card:address-data>"
                "</d:prop></d:propstat></d:response></d:multistatus>")
        return ElementTree.fromstring(NEXTCLOUD_HOME)


def test_only_the_owners_own_books_count_and_a_minute_needs_no_new_lookup():
    template = nextcloud()
    plugin = NextcloudWithCards(template.ctx, template.manifest)
    plugin.asked = []
    asked = [["email", "mallory@evil.example"], ["email", "sam@evil.example"], ["email", "LENA@example.org"]]
    assert plugin.known_recipients(asked) == {"LENA@example.org": {"name": "Léna Bakker"}}
    assert [m for m, _ in plugin.asked] == ["PROPFIND", "REPORT"]
    assert plugin.known_recipients(asked) == {"LENA@example.org": {"name": "Léna Bakker"}}
    assert len(plugin.asked) == 2  # within KNOWN_FRESH_SECONDS: the cards as they were, no PROPFIND
    plugin.read_search({})  # a read always asks whether a book changed
    assert [m for m, _ in plugin.asked[2:]] == ["PROPFIND"]

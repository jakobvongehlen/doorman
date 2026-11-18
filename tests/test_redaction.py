"""One-time codes and sign-in links: `basic` (the default) masks a code word followed by the code and reset
links; `strict` every format the big services send them in; `off` nothing. Ordinary numbers in ordinary mail
stay as they are in every mode."""

import pytest

from doorman import config
from doorman.redaction import Redactor
from conftest import FAKE_PLUGINS, Agent, make_engine

redactor = Redactor({"redaction": {**config.DEFAULTS["redaction"], "codes": "strict"}})  # default senders
basic = Redactor(config.DEFAULTS)
off = Redactor({"redaction": {**config.DEFAULTS["redaction"], "codes": "off"}})

CODES = [
    ("Your verification code is 123456", "123456"),
    ("123456 is your Google verification code", "123456"),
    ("G-482913 is your Google verification code.", "482913"),
    ("482913 is your Instagram code", "482913"),
    ("123 456 is your Facebook confirmation code", "123 456"),
    ("Use 482913 to sign in to Instagram", "482913"),
    ("Enter 4829 to verify your email address", "4829"),
    ("Dein Bestätigungscode: 4829 13", "4829 13"),
    ("482913 ist dein Bestätigungscode", "482913"),
    ("Je verificatiecode is 834201", "834201"),
    ("Your one-time passcode: AB12CD", "AB12CD"),
    ("Your Steam Guard code: F4K9Q", "F4K9Q"),
    ("Your code\n\n482913", "482913"),
    ("Microsoft account security code: 4829", "4829"),
    ("Click https://accounts.example.com/e/AbCdEf123456 to confirm your account", "AbCdEf123456"),
]

ORDINARY = [
    "Invoice 2026-118 is attached",
    "postcode 3584 CS Utrecht",
    "Postal code: 3584 CS",
    "The lecture is on 2026-11-07 at 14:30 in room 2.06",
    "Deadline 15 November 2026, 23:59",
    "Course code INFOB3TC starts in block 2",
    "Course code: 201400123",
    "Room 1.23, Buys Ballot building, course INFOB3TC",
    "We meet in room 2034 at 10:15",
    "The code of conduct for 2026 applies",
    "In 2026 the new PIN rules apply",
    "Your code review is due 2026-11-12",
    "Total: €1.234,56 (EUR 1234.56)",
    "Order 4829 confirmed, total 59.90",
    "Order number 112-4839201-5512 has shipped",
    "Your order 48291337 is on its way",
    "Booking reference AB12CD for 7 Nov",
    "Kind regards,\nJan\nTel: +31 30 253 4829\nMobile 06 12345678",
    "Mei Tan\nTel: +31 30 253 4829",
    "Confirm your booking for INFOB3TC on 12 Nov in room 0.06 at 13:15, order 4839201",
    "Please confirm the meeting https://uu-nl.zoom.us/j/81234567890?pwd=AbCdEf1234567",
    "Code review: https://docs.google.com/document/d/1AbCdEfGh2345678/edit",
    "See https://uu.brightspace.com/d2l/le/content/123456/viewContent/7890123/View",
]


@pytest.mark.parametrize("text,code", CODES)
def test_one_time_codes_are_masked(text, code):
    out = redactor.text(text)
    assert code not in out and "redacted]" in out


@pytest.mark.parametrize("text", ORDINARY)
def test_ordinary_numbers_stay(text):
    assert redactor.text(text) == text
    assert basic.text(text) == text


BASIC = ["Your verification code is 123456", "Dein Bestätigungscode: 4829 13", "Je verificatiecode is 834201",
         "Microsoft account security code: 4829"]
ONLY_STRICT = ["123456 is your Google verification code", "Use 482913 to sign in to Instagram",
               "Your one-time passcode: AB12CD", "Your code\n\n482913",
               "Click https://accounts.example.com/e/AbCdEf123456 to confirm your account"]


def test_basic_masks_a_code_after_its_word_and_reset_links_only():
    """The default: the forms most codes come in, nothing that needs guessing."""
    for text in BASIC:
        assert "redacted]" in basic.text(text)
    assert basic.text("Reset it at https://example.com/reset?token=abc") == "Reset it at [link redacted]"
    for text in ONLY_STRICT:
        assert basic.text(text) == text
    item = {"id": "m1", "from": ["security@mail.instagram.com"], "subject": "Your Instagram account: 482913"}
    assert basic.value(item) == item  # strict alone empties a security sender's subject


def test_off_masks_nothing_and_withholds_no_security_mail():
    for text, _ in CODES:
        assert off.text(text) == text
    assert not off.is_security_sender("security@mail.instagram.com")
    assert basic.is_security_sender("security@mail.instagram.com")
    with pytest.raises(ValueError, match="redaction.codes"):
        Redactor({"redaction": {"codes": "everything"}})
    assert Redactor({"redaction": {"codes": False}}).codes == "off"  # YAML's bare off


def test_an_item_from_a_security_sender_loses_every_code_but_keeps_its_id_and_date():
    item = {"id": "<CAB12345XYZ@mail.gmail.com>", "ref": "mail:<CAB12345XYZ@mail.gmail.com>",
            "from": ["Instagram <security@mail.instagram.com>"], "date": "2026-11-07T08:00:00Z",
            "subject": "Your Instagram account: 482913", "preview": "Or use AB12CD, or https://i.example/r/AbCdEfGh1234"}
    out = redactor.value(item)
    assert {k: out[k] for k in ("id", "ref", "from", "date")} == {k: item[k] for k in ("id", "ref", "from", "date")}
    assert "482913" not in out["subject"] and "AB12CD" not in out["preview"] and "AbCdEfGh1234" not in out["preview"]
    # the same subject from anyone else carries no code word, so it stays
    assert redactor.value({**item, "from": ["anna@example.com"]})["subject"] == item["subject"]


def test_a_code_in_a_subject_never_reaches_the_agent(tmp_path):
    """The subject of a mail from a security sender, in search, in the event feed: account takeover at a
    third-party service if an injected agent started a reset with the owner's address."""
    engine = make_engine(tmp_path, plugin_paths=[FAKE_PLUGINS], redaction={"codes": "strict"}, plugins={
        "mail": {"type": "fake_mail", "enabled": True}})
    box = engine.registry.instance("mail")
    agent = Agent(engine)
    engine.poll_triggers(force=True)
    box.add("inbox", "security@mail.instagram.com", "482913 is your Instagram code", "Someone tried to reset...")
    box.add("inbox", "security@mail.example.com", "Your login: 773108", "...")
    box.add("inbox", "anna@example.com", "Room 2034 at 14:30 on 2026-11-12, order 4839201", "See you")
    engine.poll_triggers(force=True)
    rows = agent.read("mail.search", {})
    events = engine.event_feed(agent.session, agent.key, 0)["events"]
    for seen in (str(rows), str(events)):
        assert "482913" not in seen and "773108" not in seen
        assert "Room 2034 at 14:30 on 2026-11-12, order 4839201" in seen.replace("ˆ", " ")
    assert {r["id"] for r in rows} == {"m1", "m2", "m3"}  # ids stay, so each can still be opened

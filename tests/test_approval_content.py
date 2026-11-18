"""An approval shows what actually goes out and which task asked for it, not just the ids in the arguments."""


def test_a_note_send_shows_the_note_and_its_task(engine, agent):
    task_id = engine.tasks.create("Share the shopping list with the flat", trusted=True)
    made = agent.call("notes.create", {"title": "Shopping", "body": "milk, oat flakes"})
    sent = agent.call("notes.send_copy", {"id": made["result"]["id"], "to": "d@example.com"}, task_id=task_id)
    entry = engine.approvals.get(sent["approval_id"])["entries"][0]
    assert entry["summary"] == "Send note “Shopping” to d@example.com"
    assert entry["outgoing"] == {"label": "Copy of your note", "title": "Shopping", "text": "milk, oat flakes"}
    assert entry["task_text"] == "Share the shopping list with the flat"


def test_a_missing_note_still_shows_the_approval(engine, agent):
    made = agent.call("notes.create", {"title": "Old"})
    sent = agent.call("notes.send_copy", {"id": made["result"]["id"], "to": "d@example.com"})
    engine.revert_entry(made["entry_id"], force=True)  # the note is gone before the owner looks
    entry = engine.approvals.get(sent["approval_id"])["entries"][0]
    assert entry["outgoing"] is None
    assert entry["summary"] == "Send note “Old” to d@example.com"  # written when the agent asked


def test_decided_entries_carry_no_preview(engine, agent):
    made = agent.call("notes.create", {"title": "Gym"})
    sent = agent.call("notes.send_copy", {"id": made["result"]["id"], "to": "d@example.com"})
    engine.approvals.decide(sent["approval_id"], approve=False)
    entry = engine.approvals.get(sent["approval_id"])["entries"][0]
    assert "outgoing" not in entry


def test_the_push_title_names_the_stake():
    """The lock screen shows the title first: who it goes to, what is paid, or the new recipient to check."""
    from doorman.approvals_util import notice_title

    send = {"tier": "irreversible", "args": {"to": "anna@uni.example", "body": "Hi"}, "summary": "Send mail"}
    assert notice_title([send]) == "Send to anna@uni.example"
    new = {**send, "untrusted_destinations": [{"value": "x@evil.example"}]}
    assert notice_title([new]) == "New recipient: x@evil.example"
    pay = {"tier": "payment", "args": {"amount": 84.2, "name": "Stadtwerke", "iban": "DE00"}}
    assert notice_title([pay]) == "Pay 84.20 € to Stadtwerke"
    mcp = {"tier": "irreversible", "args": {}, "mcp": {"server": "Notion", "tool": "create_page", "title": "Create page"}}
    assert notice_title([mcp]) == "Run Create page on Notion"
    change = {"tier": "reversible", "args": {}, "summary": "Move “Lunch” to 13:00"}
    assert notice_title([change]) == "Change waiting: Move “Lunch” to 13:00"
    assert notice_title([send, send]) == "2 sends to anna@uni.example"
    assert notice_title([send, {**send, "args": {"to": "ben@uni.example"}}]) == "2 sends waiting for you"
    assert len(notice_title([{**send, "args": {"to": "a" * 300}}])) <= 80


def test_a_grouped_push_says_how_many_which_task_and_the_stake():
    """One push for a task's sends: the count and the task, then what to look at twice (a paused key, a new
    recipient), else who they go to. The body has a line per send and sends the owner to read them."""
    from doorman.approvals_util import group_text, group_title

    def send(to, **kw):
        return {"tier": "irreversible", "args": {"to": to}, "summary": f"Send note “Plan” to {to}", **kw}
    assert group_title([send("anna@uni.example"), send("anna@uni.example")], 12) == "2 sends from task 12 to anna@uni.example"
    assert group_title([send("anna@uni.example"), send("ben@uni.example")], 12) == "2 sends from task 12 to anna@uni.example, ben@uni.example"
    new = send("x@evil.example", untrusted_destinations=[{"value": "x@evil.example"}])
    assert group_title([send("anna@uni.example"), new], 12) == "2 sends from task 12: new recipient x@evil.example"
    paused = send("anna@uni.example", key_paused="honeytoken in a mail.send call")
    assert group_title([paused, new], 12) == "2 sends from task 12: its key is paused"
    change = {"tier": "reversible", "args": {}, "summary": "Move “Lunch” to 13:00"}
    assert group_title([change, change], None) == "2 changes from the agent"
    assert len(group_title([send("a" * 50 + "@x.example") for _ in range(5)], 12)) <= 80
    text = group_text([send("anna@uni.example"), send("ben@uni.example")])
    assert text == ("· Send note “Plan” to anna@uni.example\n· Send note “Plan” to ben@uni.example\n\n"
                    "Open Doorman to read each one in full.")
    assert group_text([send("a" * 200) for _ in range(20)]).endswith("Open Doorman to read each one in full.")

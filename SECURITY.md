# Security

Doorman holds credentials and decides what an AI agent may do with them, so a flaw here matters more
than in most software. If you find one, please report it privately first.

## Reporting a problem

Use GitHub's private reporting: on the repository page, **Security → Report a vulnerability**. Say what
you found, how to reproduce it and which version or commit you used. Please don't open a public issue
for anything that lets an agent, a plugin or an outsider do more than the owner allowed.

This is a small project without a response-time promise. Reports are read, and fixes are credited
unless you'd rather not be named.

## What counts

- An agent key doing what the owner's settings forbid: a tool that is Off running, a send going out
  without its approval, an approval covering something other than what the screen showed.
- A plugin's process reaching beyond its sandbox: another plugin's credentials or folder, a host its
  manifest doesn't name.
- Credentials or vault contents reaching an agent, a log, the journal or a backup in clear text.
- The owner app reachable or usable without the owner's passkey (or password, where Doorman signs in
  with one).
- Network watch (the egress proxy) letting through what its rules say it blocks.

## What doesn't

The limits Doorman states for itself are not vulnerabilities: [Known gaps](docs/how-it-works.md#known-gaps)
names them and links to the limits of network watch, the injection guard and the other optional parts.
Two examples: the injection guard is a filter that misses some attacks, and an agent can leak
what it read through its model provider. Improvements to those are welcome as ordinary issues.

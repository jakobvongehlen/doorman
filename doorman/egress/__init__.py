"""Network watch: what the acting agent's container sends to the internet, seen by Doorman's egress proxy.

fingerprint, decode, rules, geoip and observer are the shared core and import only the standard library:
the proxy's and the observer's images copy this directory without Doorman's dependencies. service.py is
Doorman's side and may import the rest of Doorman.
"""

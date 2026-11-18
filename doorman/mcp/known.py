"""Well-known remote MCP servers the owner app offers by name, so nobody has to look an address up.

Each is run by the service itself and speaks Streamable HTTP. `id` becomes the plugin's name and picks the
logo in the owner app (BRANDS in owner_app/app.js); `token` says what to paste for a server that takes an
access token instead of a sign-in. Each address answered and, unless it has `token`, offered app registration
when this list was written (November 2026); the sign-in itself wasn't tried with an account. Addresses
change: this file is the one place to fix them.
"""

from urllib.parse import urlparse

KNOWN: list[dict] = [
    {"id": "notion", "title": "Notion", "url": "https://mcp.notion.com/mcp", "about": "Pages, databases and comments"},
    {"id": "linear", "title": "Linear", "url": "https://mcp.linear.app/mcp", "about": "Issues, projects and cycles"},
    {"id": "github", "title": "GitHub", "url": "https://api.githubcopilot.com/mcp/",
     "about": "Repositories, issues and pull requests",
     "token": "A personal access token (GitHub: Settings, Developer settings). GitHub's sign-in only takes apps "
              "registered with it, so this server needs a token."},
    {"id": "gitlab", "title": "GitLab", "url": "https://gitlab.com/api/v4/mcp",
     "about": "Projects, issues and merge requests on gitlab.com"},
    {"id": "atlassian", "title": "Atlassian", "url": "https://mcp.atlassian.com/v1/mcp",
     "about": "Jira issues and Confluence pages"},
    {"id": "sentry", "title": "Sentry", "url": "https://mcp.sentry.dev/mcp", "about": "Errors, issues and releases"},
    {"id": "todoist", "title": "Todoist", "url": "https://ai.todoist.net/mcp", "about": "Tasks and projects"},
    {"id": "airtable", "title": "Airtable", "url": "https://mcp.airtable.com/mcp", "about": "Bases, tables and records"},
    {"id": "clickup", "title": "ClickUp", "url": "https://mcp.clickup.com/mcp", "about": "Tasks, lists and docs"},
    {"id": "intercom", "title": "Intercom", "url": "https://mcp.intercom.com/mcp", "about": "Conversations and contacts"},
    {"id": "stripe", "title": "Stripe", "url": "https://mcp.stripe.com", "about": "Customers, invoices and payments"},
    {"id": "huggingface", "title": "Hugging Face", "url": "https://huggingface.co/mcp",
     "about": "Models, datasets and papers"},
]
for _entry in KNOWN:
    _entry.setdefault("token", None)


def icon_for(url: str) -> str | None:
    """The known server at this address's host, by its id; None for any other address."""
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    return next((k["id"] for k in KNOWN if host and urlparse(k["url"]).hostname == host), None)

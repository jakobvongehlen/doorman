# doorman-activity

Tells Doorman when each of the agent's tool calls starts and ends, so the Network log can say which call
(and which command) made a connection. Without it the log still works; connections just aren't tied to
tool calls. The hooks never hold up or fail a tool call: posts go out from a background thread with a 2 s
timeout, and errors are logged and dropped.

## Hermes

```sh
cp -r doorman-activity ~/.hermes/plugins/
hermes plugins enable doorman-activity
```

(or add `doorman-activity` to `plugins.enabled` in `~/.hermes/config.yaml`). Plugins are off until
enabled. It reads `DOORMAN_URL` and `DOORMAN_TOKEN` from the environment, as the `doorman` command does,
and the session `doorman claim` saved (or `DOORMAN_SESSION`), so the calls count towards the claimed task.

## Claude Code

The `doorman` command has the same hook built in. Add this to `~/.claude/settings.json` (or the
project's `.claude/settings.json`), with `DOORMAN_URL` and `DOORMAN_TOKEN` set where Claude Code runs:

```json
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "timeout": 5,
        "command": "python3 ~/.claude/skills/doorman/scripts/doorman.py activity hook"}]}
    ],
    "PostToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "timeout": 5,
        "command": "python3 ~/.claude/skills/doorman/scripts/doorman.py activity hook"}]}
    ]
  }
}
```

The hook prints nothing and always exits 0. A `PostToolUseFailure` entry with the same command, where
your Claude Code version has that event, records failed calls as `error`.

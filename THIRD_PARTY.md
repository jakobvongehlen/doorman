# Third-party material

Doorman's own code is under the MIT license ([LICENSE](LICENSE)). This lists what comes from others.

## Shipped in this repository

| What | Where | License |
| --- | --- | --- |
| Schibsted Grotesk (typeface; Copyright 2023 The Schibsted-Grotesk Project Authors, github.com/schibsted/schibsted-grotesk) | `doorman/owner_app/fonts/`, and embedded in `docs/banner.svg` | SIL Open Font License 1.1 (`doorman/owner_app/fonts/OFL.txt`) |
| Logo marks of Notion, Linear, GitHub, GitLab, Atlassian, Sentry, Todoist, Airtable, ClickUp, Intercom, Stripe and Hugging Face, from [Simple Icons](https://simpleicons.org) 16.38 | `BRANDS` in `doorman/owner_app/app.js`, shown beside those services' MCP servers | CC0 1.0 for the icon files. The marks are trademarks of their owners, used only to name the service; Doorman is not affiliated with or endorsed by any of them. |

## Downloaded when you switch a feature on

Nothing here is part of the repository or the Docker image. Each is fetched from its publisher; the two
models are pinned to one revision and checked against their sha256.

| What | Used for | From | License |
| --- | --- | --- | --- |
| Wolf Defender Small v2 (FP16 ONNX build) | the injection guard | huggingface.co/patronus-studio/wolf-defender-prompt-injection-small | Apache-2.0 |
| Granite Embedding 107M multilingual (uint8 ONNX build by gety-ai; the model is IBM's) | semantic search | huggingface.co/gety-ai/granite-embedding-107m-multilingual-onnx | Apache-2.0 |
| IP to Country Lite | network watch's country rule (`EGRESS_GEOIP=0` skips it) | db-ip.com | CC BY 4.0: "IP Geolocation by DB-IP" |

## Built into the Docker images

| What | Image | License |
| --- | --- | --- |
| Python packages named in `deploy/requirements.lock`, `deploy/reader.lock` and `deploy/egress/requirements.lock` | Doorman, the reader, the egress proxy | each package's own; among them RapidOCR with the PP-OCRv6 models (Apache-2.0) and mitmproxy (MIT) |
| [wacli](https://github.com/steipete/wacli) | the WhatsApp sidecar (`sidecars/whatsapp/`), built from source at a pinned tag | MIT |

## Client IDs

The Microsoft 365 mail and Teams plugins sign in with Mozilla Thunderbird's public OAuth client ID
unless you set an app registration of your own (`client_id`). It is a public identifier without a
secret, used the way `mutt_oauth2.py` and `email-oauth2-proxy` use it; your sign-ins then show up as
"Mozilla Thunderbird" in your account. Doorman is not affiliated with Mozilla or Microsoft.
[Setting up plugins](docs/plugins.md) says how to use your own registration instead.

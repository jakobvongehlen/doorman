"""A bank that writes its transfers into a file instead of making them: what the payment tier is tested with."""

import json
from decimal import Decimal

from doorman import clock
from doorman.plugin_api import BasePlugin, ExecResult, Tool


class PrepareTransfer(Tool):
    def execute(self, args, before):
        amount = Decimal(str(args["amount"])).quantize(Decimal("0.01"))
        with open(self.ctx.data_dir / "transfers.jsonl", "a") as fh:
            fh.write(json.dumps({**args, "amount": str(amount), "ts": clock.iso()}) + "\n")
        return ExecResult(result={"written_down": True},
                          summary=f"Transferred {amount} EUR to {args['name']} ({args['iban']})")

    def describe(self, args):
        return f"Transfer {args.get('amount')} EUR to {args.get('name')} ({args.get('iban')}): {args.get('reference', '')}"

    def follow_up(self, args, result):
        return f"Ask {args.get('name')} for a refund, or ask your bank about recalling the transfer."


class Plugin(BasePlugin):
    TOOLS = {"prepare_transfer": PrepareTransfer}
    READS = {"balance": "read_balance"}

    def read_balance(self, params):
        return {"iban": self.config.get("iban"), "amount": 1234.5, "currency": "EUR", "date": "2026-11-03"}

import typing

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import flow
from mitmproxy import types


class FlowFuzzer:

    def replay_flow_with_replacements(
            self,
            flow,
            match,
            replacements
        ):

        for replacement in replacements:
            dup = flow.copy()
            dup.request.replace(match, replacement)
            # Only interactive tools have a view. If we have one, add a duplicate entry
            # for our flow.
            if "view" in ctx.master.addons:
                ctx.master.commands.call("view.flows.add", [dup])
            ctx.master.commands.call("replay.client", [dup])

    @command.command("flow.fuzzer")
    def fuzz_with_replace(
            self,
            flow: flow.Flow,
            path: types.Path,
            match: str
    ) -> None:

        # Avoid an infinite loop by not replaying already replayed requests
        if flow.request.is_replay:
            return

        with open(path) as f:
            self.replay_flow_with_replacements(flow, match, f.read().splitlines())

addons = [
    FlowFuzzer()
]

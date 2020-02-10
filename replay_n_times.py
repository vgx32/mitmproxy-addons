from mitmproxy import ctx

def replay_flow_with_replacements(flow, match, replacements):
    for replacement in replacements:
        dup = flow.copy()
        dup.request.replace(match, replacement)
        # Only interactive tools have a view. If we have one, add a duplicate entry
        # for our flow.
        if "view" in ctx.master.addons:
            ctx.master.commands.call("view.flows.add", [dup])
        ctx.master.commands.call("replay.client", [dup])

def request(flow):

    # Avoid an infinite loop by not replaying already replayed requests
    if flow.request.is_replay:
        return

    filepath = "test_vals.txt"
    match = "keep"
    with open(filepath) as f:
        replay_flow_with_replacements(flow, match, f.read().splitlines())


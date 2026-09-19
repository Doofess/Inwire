"""The agent's version, which is Inwire's version.

**Generated. Do not edit by hand** - run `npm run sync:version`, which writes
this file from `package.json`. `scripts/agent/version.ts` fails the build if the
two disagree, so an edit here is a check failure rather than a silent fork.

## Why the agent stopped carrying a number of its own

It had one because it used to be installed on its own, from its own installer,
against a web page that might be any age. Neither half of that is true any
more: one installer carries the app and the agent together (ADR 0030), they are
built from one repository, and they are replaced in one transaction. Two numbers
for two halves that cannot be apart is two numbers that can only ever disagree
by mistake - and they did, across six stamps, three of which were checked by
different scripts covering different subsets.

What the number still has to be is an **ordering**. It is the left-hand side of
`isAgentOutdated`, so an agent left behind by an earlier install has to read as
older rather than newer; a version that goes backwards shows in the UI as "not
connected", which is a state with no instruction attached to it. That is the
whole reason the product's own number jumped to 4.0.0 rather than the agent's
dropping to 1.0.0: the unified number has to be at least the highest either half
ever shipped, and the agent had shipped 3.9.0.
"""

AGENT_VERSION = "4.0.0"

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

It is compared for **equality**, not order (ADR 0051): the app asks whether the
agent it reached is from its own build, and an agent reporting any other number
is one a different install left behind. That is what let the number go down to
0.x, where an ordering had held it at 4.x.
"""

AGENT_VERSION = "0.4.1"

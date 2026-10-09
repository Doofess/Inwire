# Installing Npcap silently, or shipping a copy of it

**Rejected:** `/S` on Npcap's installer anywhere, for any reason, and a mirrored or bundled copy of Npcap.

**Why:** silent install is Npcap's OEM feature and the free licence does not grant it. The wizard is shown because its licence is shown with it. Npcap is fetched from npcap.com or not at all, so the user installs the real thing under its own terms. Npcap is a prerequisite the app manages through the Update Center, not a payload the installer ships.

**Rests on:** ADR 0032.

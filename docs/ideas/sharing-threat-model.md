# A threat model for capture sharing that is not built

> **Nothing described here exists.** There is no account, no backend, no
> Firestore and no sharing feature anywhere in this repository, and the product
> direction in `CLAUDE.md` is the opposite one: everything local, offline by
> default. This file is kept for one reason only — if sharing is ever built, the
> twelve payloads below are the acceptance matrix it would have to pass, and
> rederiving them later would be wasted work. Read it as a wish list with a test
> plan attached, never as a description of this code.
>
> It moved here from a root-level `security_spec.md`, which read as a
> description of the app and repeatedly had to be explained away.

## The data invariants it would have to hold

1. Users may only read and write their own profile document unless they are
   verified admins.
2. Admins are validated server-side against an `admins` collection keyed by the
   authenticated uid — never from a client-supplied claim.
3. Role privilege escalation is blocked: a regular user cannot modify their own
   `role` field.
4. All document IDs conform to `^[a-zA-Z0-9_\-]+$` and are at most 128 chars.
5. A shared capture can only be created by an authenticated user whose
   `authorId` equals their own uid.

The first admin would have to be bootstrapped out of band. Which account that is
is a deployment decision and deliberately not recorded here.

## The dirty dozen — every one must be denied

1. **Unauthenticated profile read** — an anonymous request listing all users.
2. **Identity spoofing on registration** — an authenticated user creating a
   profile document under somebody else's uid.
3. **Privilege escalation** — setting `role: "ADMIN"` on one's own profile
   without being an admin.
4. **Admin self-creation** — a non-admin creating their own entry in `admins`.
5. **ID poisoning** — a document id of 2 kB of junk characters.
6. **Shadow field injection** — smuggling `isSuperUser: true` into a profile
   update.
7. **Capture author spoofing** — creating a shared capture with `authorId` set
   to a victim's uid.
8. **Capture tampering** — a non-author, non-admin updating somebody else's
   shared capture.
9. **Deletion by a non-owner** — a non-author deleting a capture.
10. **Admin list modification** — a non-admin revoking an admin's permissions.
11. **Excessive payload** — a 50 kB title on a shared capture.
12. **Unverified email impersonation** — claiming an admin's address with
    `email_verified == false`.

Each is a test, not a prose assurance: the point of the list is that a rules
change is held to twelve runnable denials rather than to a reading of the rules.

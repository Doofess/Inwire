# Security Specification & Threat Model

## Data Invariants
1. Users may only read and write their own UserProfile document unless they are verified Admins.
2. Admins are validated exclusively via `exists(/databases/$(database)/documents/admins/$(request.auth.uid))` - never client-side claims.
3. Bootstrapped admin is `Rotem2207@gmail.com`.
4. Role privilege escalation is blocked: regular users cannot modify their own `role` field.
5. All document IDs must conform to `^[a-zA-Z0-9_\-]+$` and size <= 128 chars.
6. Shared captures can only be created by authenticated users whose `authorId == request.auth.uid`.

## The Dirty Dozen Security Test Payloads (All MUST return PERMISSION_DENIED)
1. **Unauthenticated User Profile Read**: Anonymous request attempting to list `/users`.
2. **Identity Spoofing on User Registration**: Authenticated user trying to create `/users/other-uid`.
3. **Privilege Escalation**: Authenticated user attempting to set `role: "ADMIN"` on their own profile without being in `/admins`.
4. **Admin Document Self-Creation**: Non-admin user trying to create `/admins/$(request.auth.uid)`.
5. **ID Poisoning Attack**: Attempting to write document with 2KB junk characters in `{userId}`.
6. **Shadow Field Injection**: Writing ghost fields (`isSuperUser: true`) during profile updates.
7. **Capture Author Spoofing**: Creating a shared capture with `authorId` set to a victim's UID.
8. **Malicious Capture Tampering**: Non-author non-admin trying to update another user's shared capture.
9. **Capture Deletion by Non-Owner**: Non-author trying to delete a capture.
10. **Admin List Modification by Non-Admin**: Analyst trying to revoke admin permissions.
11. **Excessive String Payload Attack**: Writing a 50KB title in shared capture.
12. **Unverified Email Impersonation**: Spoofing admin email with `email_verified == false`.

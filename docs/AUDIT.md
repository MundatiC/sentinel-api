# Code audit (ponytail method)

Audited the whole repo like the developer who inherited it: correct, safe, holds under load, tested, fast, lean.
Assumed load: a small team (a few users) plus a few scanners and log shippers sending batches, on **one API instance**.
Every finding below was reproduced with a failing test before it was fixed.

| #   | Finding                                                                   | Case                                                                                                                                                                                                  | Status                                                                                                                       |
| --- | ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Must fix.** Simultaneous sign-ups for one email returned 500            | Three parallel `POST /auth/register` with the same email returned `[201, 500, 500]`: the "does it exist?" check passes for all, then the database rejects the duplicates and the error was not caught | Fixed: unique-index error becomes `409 EMAIL_TAKEN`                                                                          |
| 2   | **Must fix.** A resolved alert could be set back to acknowledged          | An analyst resolves while another acknowledges at the same moment: both pass the status check, the last write wins, and the alert ended `ACKNOWLEDGED` with `resolvedAt` set                          | Fixed: the update only applies if the status is still what was checked, otherwise `409 CONFLICT`                             |
| 3   | **Must fix.** One alert could be linked into two incidents                | Two analysts link the same alert to different incidents at once: both succeed and both timelines claim it                                                                                             | Fixed: linking claims the alert only while it has no incident, otherwise `409 ALERT_ALREADY_LINKED`                          |
| 4   | **Should fix.** The refresh-token table only grows                        | Each login and refresh adds a row and nothing deleted expired or long-revoked ones                                                                                                                    | Fixed: dead rows are pruned at login (recently revoked rows stay, so token-theft detection still works); `expiresAt` indexed |
| 5   | **Nice to have.** `eventInput` was exported but used only in its own file | knip                                                                                                                                                                                                  | Fixed                                                                                                                        |

Checked and **not** findings: `pino-pretty` and the Prisma generator look unused to static tools but are loaded by name;
`AuthUser`/`AuthApiKey` are exported for the Express type augmentation.

Known limits kept on purpose (see THREAT_MODEL.md): in-memory rate limiting and live-feed bus (one instance), no event retention policy
(events and audit entries grow; add a scheduled delete if volume matters), no ingest idempotency keys (a retried batch is stored twice).

Not checked: behaviour under real concurrent load (only the races above were tested), the Docker image (no daemon in the dev sandbox).

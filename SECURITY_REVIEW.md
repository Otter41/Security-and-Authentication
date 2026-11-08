# SafeVault Security Review

## What needed fixing

The original exercise described three main risks: SQL queries built from user input, unescaped text rendered as HTML, and missing checks around who can access sensitive data.

I treated those as the things to fix first rather than adding a bunch of unrelated features.

## Changes I made

**SQL injection:** All database lookups and inserts use SQLite parameters. An input like `admin' OR 1=1 --` is passed as plain text, not SQL. The login and record tests include injection-like inputs.

**Input validation:** Registration checks usernames, email addresses and password lengths. I didn't try to remove every quote or special character from notes because that would destroy valid data. Parameters and context-specific output encoding are the actual protections.

**XSS:** The HTML preview uses `HtmlEncoder`, and the test verifies that script tags are encoded rather than rendered. Stored notes are returned as JSON, not injected into HTML.

**Authentication:** bcrypt hashes passwords before they are stored. Login uses a secure session cookie and the same failure response for invalid credentials.

**Authorization:** Everyone who registers gets the User role. Only an admin created through server configuration can open `/admin/users`. Records are filtered by the ID in the authenticated session, so one user can't read another user's records.

## Tests and debugging

I added xUnit integration tests for the cases the assignment asks about: invalid data, SQL injection-like usernames and notes, XSS output, failed login, access without a session, role escalation, duplicate accounts, and record privacy.

The tests use a temporary SQLite database. I ran them through GitHub Actions on 8 November 2026: **8/8 passed, with zero build warnings or errors**. The repository includes the workflow so reviewers can check the result themselves.

## How the LLM helped

I used ChatGPT to review the SafeVault requirements and turn the security problems into concrete code and test cases. It helped with the parameterized SQLite implementation, bcrypt login flow, role-based authorization, HTML output encoding, and the test coverage.

One suggestion I didn't follow was trying to strip every suspicious character from user input. That can break normal content, and it doesn't replace safe database queries or output encoding.

The biggest improvements were moving SQL inputs into parameters, hashing passwords properly, and checking roles and record ownership on the server instead of trusting the client.

**Copilot note:** This draft documents ChatGPT assistance. The Coursera rubric specifically asks about Microsoft Copilot, so I still need to run a real Copilot review and add its actual suggestions here before claiming Copilot helped.

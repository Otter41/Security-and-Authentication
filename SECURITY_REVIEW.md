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

I added xUnit integration tests for the cases the assignment asks about: invalid data, SQL injection-like usernames and notes, XSS output, failed login, access without a session, role escalation, duplicate accounts, bcrypt's 72-byte password limit, and record privacy.

The tests use a temporary SQLite database. I ran them through GitHub Actions on 8 November 2026: **9/9 passed, with zero build warnings or errors**. The repository includes the workflow so reviewers can check the result themselves.

## How Copilot helped

I used Microsoft Copilot to review the security risks and help with the fixes for SQL injection, XSS, input validation, authentication, and access control. It also helped me work through the test cases so I could check that the protections actually worked.

I kept user input as data instead of trying to remove every suspicious character. Parameterized queries protect the database, while output encoding protects HTML. The biggest improvements were secure database queries, password hashing, and checking permissions on the server.

# SafeVault

A small ASP.NET Core 8 security assignment. It has user registration, login, admin/user roles, and private records backed by SQLite.

## Run it

Requires .NET 8 SDK. No database server needed.

In PowerShell:

```powershell
dotnet dev-certs https --trust
$env:SafeVault__AdminPassword = "choose-your-own-long-password"
dotnet run --project SafeVault --launch-profile SafeVault
```

Open https://localhost:7129/health to check that the API started. On first startup, the admin account is created with username `admin` and the password you set in the environment variable. Don't commit a real password or put it into appsettings.

To run the security tests:

```powershell
dotnet test SafeVault.Tests/SafeVault.Tests.csproj
```

GitHub Actions also runs these tests on pushes.

## API routes

| Method | Route | Access |
| --- | --- | --- |
| GET | /health | Everyone |
| POST | /register | Everyone |
| POST | /login | Everyone |
| POST | /logout | Logged-in users |
| GET | /records | Logged-in users, own records only |
| POST | /records | Logged-in users, own records only |
| GET | /admin/users | Admin only |
| GET | /preview?text=... | Everyone; encoded HTML demo |

Register JSON: `{ "username": "alice", "email": "alice@example.com", "password": "a-long-test-password" }`

Login JSON: `{ "username": "alice", "password": "a-long-test-password" }`

Record JSON: `{ "label": "Lunch", "amountCents": 1250, "notes": "Example" }`

Use HTTPS for login and the session cookie. Amounts are stored as integer cents to avoid rounding problems.

## What I secured

- **SQL injection:** SQLite parameters are used for login, account creation and record operations. User text never gets joined into a SQL query.
- **Input validation:** username, email, password and record fields are checked, with length limits. Text doesn't need to be destructively stripped when SQL is parameterized and HTML is encoded.
- **Passwords:** bcrypt hashes with a per-password salt. Only the hash is stored. Registration accepts passwords of at least 12 characters and at most 72 UTF-8 bytes, so bcrypt can't silently truncate them.
- **Authentication and RBAC:** an HTTPS-only, HttpOnly, SameSite=Strict session cookie. Normal users can't open admin routes or grant themselves the Admin role.
- **XSS:** user text rendered as HTML is encoded; JSON responses stay JSON. Security headers include a strict Content Security Policy.
- **Tests:** registration, password hashing, SQL injection attempts, script input, HTML encoding, user/admin access, logout, duplicate email and record ownership.

This is a learning project, not a production vault. A deployed financial application also needs a complete threat model, stronger account lifecycle controls, abuse prevention, backup/encryption planning, and a security review.

See [SECURITY_REVIEW.md](SECURITY_REVIEW.md) for the debugging summary and LLM contribution notes.

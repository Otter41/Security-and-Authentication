using System.Net.Mail;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SafeVault;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<VaultStore>();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "SafeVault.Session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.SlidingExpiration = false;

        // APIs should return status codes, not login-page redirects.
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = 401;
            return Task.CompletedTask;
        };
        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode = 403;
            return Task.CompletedTask;
        };
    });

builder.Services.AddAuthorization(options =>
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin")));

var app = builder.Build();
app.Services.GetRequiredService<VaultStore>().Initialize();

// Basic browser protection. We don't return untrusted HTML without encoding it.
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'none'; frame-ancestors 'none'";
    await next(context);
});

if (!app.Environment.IsDevelopment())
    app.UseHsts();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/register", (RegisterRequest request, VaultStore store) =>
{
    var username = request.Username?.Trim();
    var email = request.Email?.Trim();

    // Don't try to "remove SQL" from input. Validate fields and parameterize queries.
    if (username is null || !Regex.IsMatch(username, @"^[A-Za-z0-9_.-]{3,32}$"))
        return Results.BadRequest(new { error = "Username must be 3-32 letters, numbers, dots, dashes or underscores." });

    if (email is null || email.Length > 254 ||
        !MailAddress.TryCreate(email, out var parsed) || parsed.Address != email)
        return Results.BadRequest(new { error = "Invalid email address." });

    // bcrypt only uses the first 72 UTF-8 bytes, so reject longer passwords.
    if (request.Password is null || request.Password.Length < 12 ||
        Encoding.UTF8.GetByteCount(request.Password) > 72)
        return Results.BadRequest(new { error = "Password must be at least 12 characters and at most 72 UTF-8 bytes." });

    // bcrypt salts and hashes the password. No plaintext password goes into SQLite.
    var hash = BCrypt.Net.BCrypt.HashPassword(request.Password, workFactor: 11);

    if (!store.TryCreateUser(username, email, hash, "User"))
        return Results.Conflict(new { error = "Username or email already exists." });

    return Results.StatusCode(201);
});

app.MapPost("/login", async (LoginRequest request, VaultStore store, HttpContext context) =>
{
    if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrEmpty(request.Password) ||
        Encoding.UTF8.GetByteCount(request.Password) > 72)
        return Results.BadRequest(new { error = "Username and password are required." });

    var user = store.FindByUsername(request.Username.Trim());

    // Same response for bad usernames and bad passwords.
    if (user is null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        return Results.Unauthorized();

    var claims = new[]
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Role, user.Role)
    };

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    await context.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(identity));

    return Results.Ok(new { message = "Logged in.", role = user.Role });
});

app.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.NoContent();
}).RequireAuthorization();

// Only admins can see the user directory. Password hashes aren't returned.
app.MapGet("/admin/users", (VaultStore store) =>
    Results.Ok(store.GetPublicUsers())).RequireAuthorization("AdminOnly");

app.MapGet("/records", (ClaimsPrincipal user, VaultStore store) =>
{
    var ownerId = long.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!);
    return Results.Ok(store.GetRecords(ownerId));
}).RequireAuthorization();

app.MapPost("/records", (RecordRequest request, ClaimsPrincipal user, VaultStore store) =>
{
    if (string.IsNullOrWhiteSpace(request.Label) || request.Label.Length > 80 ||
        request.AmountCents is < 0 or > 100_000_000_000 ||
        (request.Notes?.Length ?? 0) > 1000)
        return Results.BadRequest(new { error = "Invalid record." });

    var ownerId = long.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!);
    var record = store.AddRecord(ownerId, request.Label.Trim(),
        request.AmountCents, request.Notes?.Trim() ?? "");

    return Results.Created($"/records/{record.Id}", record);
}).RequireAuthorization();

// A tiny HTML endpoint to demonstrate that untrusted text gets encoded.
app.MapGet("/preview", (string? text) =>
{
    var safeText = HtmlEncoder.Default.Encode((text ?? "")[..Math.Min(text?.Length ?? 0, 200)]);
    return Results.Content("<p>" + safeText + "</p>", "text/html");
});

app.Run();

// Makes the app available to the integration test host.
public partial class Program { }

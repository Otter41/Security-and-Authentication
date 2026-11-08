using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SafeVault;
using Xunit;

public class SecurityTests
{
    private const string TestPassword = "OnlyForTheseTests123!";
    private const string AdminPassword = "TestOnlyAdminPassword123!";

    private sealed class TestApp : WebApplicationFactory<Program>
    {
        private readonly string dbPath = Path.Combine(
            Path.GetTempPath(), "safevault-test-" + Guid.NewGuid().ToString("N") + ".db");

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseSetting("SafeVault:DbPath", dbPath);
            builder.UseSetting("SafeVault:AdminPassword", AdminPassword);
        }

        public HttpClient NewClient() => CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = false
        });
    }

    private static async Task Register(HttpClient client, string username, string? email = null)
    {
        var response = await client.PostAsJsonAsync("/register", new
        {
            username,
            email = email ?? username + "@example.com",
            password = TestPassword
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    private static async Task Login(HttpClient client, string username, string password = TestPassword)
    {
        var response = await client.PostAsJsonAsync("/login", new { username, password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task PasswordsAreHashedAndGoodCredentialsCanLogIn()
    {
        using var app = new TestApp();
        using var client = app.NewClient();
        await Register(client, "alice");

        var stored = app.Services.GetRequiredService<VaultStore>().FindByUsername("alice");
        Assert.NotNull(stored);
        Assert.NotEqual(TestPassword, stored.PasswordHash);
        Assert.StartsWith("$2", stored.PasswordHash);

        await Login(client, "alice");
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/records")).StatusCode);
    }

    [Fact]
    public async Task SqlInjectionDoesNotBypassLogin()
    {
        using var app = new TestApp();
        using var client = app.NewClient();

        // Correct admin password, but a malicious username must NEVER match an account.
        var response = await client.PostAsJsonAsync("/login", new
        {
            username = "admin' OR 1=1 --",
            password = AdminPassword
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        // The real admin should still be able to log in.
        await Login(client, "admin", AdminPassword);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/admin/users")).StatusCode);
    }

    [Fact]
    public async Task FormValidationRejectsScriptNamesAndBadEmails()
    {
        using var app = new TestApp();
        using var client = app.NewClient();

        var badName = await client.PostAsJsonAsync("/register", new
        {
            username = "<script>alert(1)</script>",
            email = "valid@example.com",
            password = TestPassword
        });
        Assert.Equal(HttpStatusCode.BadRequest, badName.StatusCode);

        var badEmail = await client.PostAsJsonAsync("/register", new
        {
            username = "bob",
            email = "not an email",
            password = TestPassword
        });
        Assert.Equal(HttpStatusCode.BadRequest, badEmail.StatusCode);

        var weakPassword = await client.PostAsJsonAsync("/register", new
        {
            username = "bob",
            email = "bob@example.com",
            password = "short"
        });
        Assert.Equal(HttpStatusCode.BadRequest, weakPassword.StatusCode);
    }

    [Fact]
    public async Task HtmlOutputIsEncodedToPreventXss()
    {
        using var app = new TestApp();
        using var client = app.NewClient();

        const string payload = "<script>alert(1)</script>";
        var response = await client.GetAsync("/preview?text=" + Uri.EscapeDataString(payload));
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("&lt;script&gt;", html);
        Assert.DoesNotContain("<script>", html);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
    }

    [Fact]
    public async Task AnonymousUsersAreBlockedAndRegularUsersAreNotAdmins()
    {
        using var app = new TestApp();
        using var client = app.NewClient();

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/records")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/admin/users")).StatusCode);

        // Extra JSON fields cannot make a normal registered user an admin.
        var response = await client.PostAsJsonAsync("/register", new
        {
            username = "alice",
            email = "alice@example.com",
            password = TestPassword,
            role = "Admin"
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        await Login(client, "alice");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/admin/users")).StatusCode);
    }

    [Fact]
    public async Task InvalidLoginAndLogoutAreHandled()
    {
        using var app = new TestApp();
        using var client = app.NewClient();
        await Register(client, "alice");

        var wrong = await client.PostAsJsonAsync("/login", new
        {
            username = "alice",
            password = "NotTheRightPassword"
        });
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);

        await Login(client, "alice");
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/logout", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/records")).StatusCode);
    }

    [Fact]
    public async Task RecordsStayPrivateAndSqlLikeNotesAreStoredAsData()
    {
        using var app = new TestApp();
        using var alice = app.NewClient();
        using var bob = app.NewClient();

        await Register(alice, "alice");
        await Register(bob, "bob");
        await Login(alice, "alice");
        await Login(bob, "bob");

        const string dangerousText = "'; DROP TABLE Users; -- <script>alert(1)</script>";
        var created = await alice.PostAsJsonAsync("/records", new
        {
            label = "Lunch",
            amountCents = 1250,
            notes = dangerousText
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        var own = await alice.GetFromJsonAsync<VaultRecord[]>("/records");
        var others = await bob.GetFromJsonAsync<VaultRecord[]>("/records");

        Assert.Single(own!);
        Assert.Equal(dangerousText, own![0].Notes);
        Assert.Empty(others!);

        // The parameterized INSERT didn't execute the SQL inside the note.
        await Login(alice, "admin", AdminPassword);
        Assert.Equal(HttpStatusCode.OK, (await alice.GetAsync("/admin/users")).StatusCode);
    }

    [Fact]
    public async Task DuplicateEmailCannotBeRegisteredTwice()
    {
        using var app = new TestApp();
        using var client = app.NewClient();

        await Register(client, "alice", "shared@example.com");
        var duplicate = await client.PostAsJsonAsync("/register", new
        {
            username = "bob",
            email = "shared@example.com",
            password = TestPassword
        });

        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
    }
}

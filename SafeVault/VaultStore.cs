using Microsoft.Data.Sqlite;

namespace SafeVault;

public sealed class VaultStore
{
    private readonly string connectionString;
    private readonly IConfiguration configuration;

    public VaultStore(IConfiguration configuration, IHostEnvironment environment)
    {
        this.configuration = configuration;

        var dbPath = configuration["SafeVault:DbPath"]
            ?? Path.Combine(environment.ContentRootPath, "safevault.db");

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(dbPath))!);

        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath
        }.ToString();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        return connection;
    }

    public void Initialize()
    {
        using (var connection = Open())
        using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                CREATE TABLE IF NOT EXISTS Users (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    Email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    PasswordHash TEXT NOT NULL,
                    Role TEXT NOT NULL CHECK (Role IN ('User', 'Admin'))
                );
                CREATE TABLE IF NOT EXISTS VaultRecords (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    OwnerId INTEGER NOT NULL REFERENCES Users(Id),
                    Label TEXT NOT NULL,
                    AmountCents INTEGER NOT NULL,
                    Notes TEXT NOT NULL
                );
                """;
            command.ExecuteNonQuery();
        }

        // An admin can only be seeded through configuration, never registration.
        // Supply the password as an environment variable, not in this repo.
        var adminPassword = configuration["SafeVault:AdminPassword"];
        if (!string.IsNullOrEmpty(adminPassword))
        {
            if (adminPassword.Length < 12)
                throw new InvalidOperationException("Admin bootstrap password must be at least 12 characters.");

            var adminName = configuration["SafeVault:AdminUsername"] ?? "admin";
            if (FindByUsername(adminName) is null)
            {
                var hash = BCrypt.Net.BCrypt.HashPassword(adminPassword, 11);
                TryCreateUser(adminName, "admin@safevault.local", hash, "Admin");
            }
        }
    }

    public bool TryCreateUser(string username, string email, string passwordHash, string role)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Users (Username, Email, PasswordHash, Role)
            VALUES ($username, $email, $hash, $role);
            """;

        // Parameters stop input from ever becoming SQL syntax.
        command.Parameters.AddWithValue("$username", username);
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$hash", passwordHash);
        command.Parameters.AddWithValue("$role", role);

        try
        {
            return command.ExecuteNonQuery() == 1;
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            return false;
        }
    }

    public StoredUser? FindByUsername(string username)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT Id, Username, Email, PasswordHash, Role
            FROM Users WHERE Username = $username;
            """;
        command.Parameters.AddWithValue("$username", username);

        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new StoredUser(reader.GetInt64(0), reader.GetString(1),
                reader.GetString(2), reader.GetString(3), reader.GetString(4))
            : null;
    }

    public IReadOnlyList<PublicUser> GetPublicUsers()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, Username, Email, Role FROM Users ORDER BY Id;";

        using var reader = command.ExecuteReader();
        var users = new List<PublicUser>();

        while (reader.Read())
            users.Add(new PublicUser(reader.GetInt64(0), reader.GetString(1),
                reader.GetString(2), reader.GetString(3)));

        return users;
    }

    public VaultRecord AddRecord(long ownerId, string label, long amountCents, string notes)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO VaultRecords (OwnerId, Label, AmountCents, Notes)
            VALUES ($owner, $label, $amount, $notes);
            SELECT last_insert_rowid();
            """;

        command.Parameters.AddWithValue("$owner", ownerId);
        command.Parameters.AddWithValue("$label", label);
        command.Parameters.AddWithValue("$amount", amountCents);
        command.Parameters.AddWithValue("$notes", notes);

        var id = (long)command.ExecuteScalar()!;
        return new VaultRecord(id, ownerId, label, amountCents, notes);
    }

    public IReadOnlyList<VaultRecord> GetRecords(long ownerId)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT Id, OwnerId, Label, AmountCents, Notes
            FROM VaultRecords WHERE OwnerId = $owner ORDER BY Id;
            """;
        command.Parameters.AddWithValue("$owner", ownerId);

        using var reader = command.ExecuteReader();
        var records = new List<VaultRecord>();

        while (reader.Read())
            records.Add(new VaultRecord(reader.GetInt64(0), reader.GetInt64(1),
                reader.GetString(2), reader.GetInt64(3), reader.GetString(4)));

        return records;
    }
}

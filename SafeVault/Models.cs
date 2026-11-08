namespace SafeVault;

// Only the fields we actually accept. The client never gets to choose its own role.
public sealed record RegisterRequest(string? Username, string? Email, string? Password);
public sealed record LoginRequest(string? Username, string? Password);
public sealed record RecordRequest(string? Label, long AmountCents, string? Notes);

public sealed record StoredUser(long Id, string Username, string Email, string PasswordHash, string Role);
public sealed record PublicUser(long Id, string Username, string Email, string Role);
public sealed record VaultRecord(long Id, long OwnerId, string Label, long AmountCents, string Notes);

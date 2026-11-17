# Local/staging laboratory permit

The Server resilience laboratory uses one client and one exact GET endpoint.
It does not run on production permits, follow redirects, use proxies, reuse
scan credentials, bypass rate limits, or create distributed traffic.

Before **Verify laboratory permit**, authorize the server in the project and
check the ownership/permission box. Verification sends one lightweight GET to:

`https://<origin>/.well-known/odin-load-test?challenge=<fresh nonce>`

Publish this handler only when the server administrator explicitly enables lab
testing in Development/Staging. The response must be JSON, echo the challenge,
and authorize the exact origin, resolved server IP and GET path. Wildcards,
expired permits, other origins/ports, and production environments are rejected.
The app re-verifies before every run and pins connections to that verified IP.
HTTP is allowed only on loopback; other targets require trusted HTTPS. On an
Android device, loopback means that device, not the developer's PC.

The application envelope is 50 concurrent users, 100 RPS, 600 seconds,
a 30-second timeout and 30,000 planned requests. Server policy can only narrow
these bounds. Zero does **not** mean unlimited in this module. Risk colors use
`max(requested RPS / capacity RPS, users / capacity users)` multiplied by the
observed P95/baseline latency ratio (at least 1). Thresholds are .35, .65 and 1.
Red does not block a configuration that satisfies all administrator ceilings.

## ASP.NET Core example (server-side integration, not executed by this project)

Use administrator configuration for the public origin and approved IPs. Do not
build the policy from request Host headers or client-supplied limits. Keep the
load-test GET handler read-only and connect it to the workloads you intend to
measure. Retain existing network ACLs, authentication, and rate limiting.

```csharp
if ((app.Environment.IsDevelopment() || app.Environment.IsStaging()) &&
    app.Configuration.GetValue<bool>("LoadLab:Enabled"))
{
    app.MapGet("/.well-known/odin-load-test", (HttpRequest request) =>
    {
        var challenge = request.Query["challenge"].ToString();
        if (!System.Text.RegularExpressions.Regex.IsMatch(
                challenge, "^[A-Za-z0-9_-]{32}$"))
            return Results.BadRequest();

        return Results.Json(new
        {
            schemaVersion = 1,
            purpose = "odinsecurity-load-test",
            challenge,
            origin = app.Configuration["LoadLab:Origin"],
            environment = app.Environment.IsStaging() ? "staging" : "local",
            permitId = "lab-policy-v1",
            allowedAddresses = app.Configuration
                .GetSection("LoadLab:AllowedAddresses").Get<string[]>(),
            allowedPaths = new[] { "/load-test/health" },
            expiresAt = DateTime.UtcNow.AddMinutes(15).ToString("O"),
            maxConcurrentUsers = 10,
            maxRps = 20,
            maxDurationSeconds = 120,
            maxTimeoutSeconds = 10,
            maxTotalRequests = 2400,
            capacityUsers = 5,
            capacityRps = 10,
            baselineLatencyMs = 100,
            stopLatencyMs = 2000,
            stopErrorPercent = 20,
            minimumSamples = 20
        });
    });

    app.MapGet("/load-test/health", () => Results.Json(new { status = "ok" }));
}
```

Example administrator configuration (replace the origin/IP with actual values):

```json
{
  "LoadLab": {
    "Enabled": true,
    "Origin": "https://staging.example.test",
    "AllowedAddresses": ["<actual server IP returned by DNS>"]
  }
}
```

Permits expire within an hour and must remain valid for the full configured run.
`capacityUsers`, `capacityRps` and `baselineLatencyMs` describe the administrator's
measured baseline; they are estimates used by the indicator, not measured server
telemetry. Hard stop thresholds apply to the most recent 100 completed attempts
once `minimumSamples` (5–100) have been collected. A 429 or 503 stops immediately,
closes active connections, and imposes the server's Retry-After cooldown (60
seconds when absent/invalid). No automatic retry is performed. Switching apps,
closing the screen or pressing Stop cancels the run. Only one load run may be
active in this app process.

Latency is time to response headers with 1 ms quantile resolution; timeout and
cancel counts are separate. At most a small body prefix is discarded; bodies and
credentials are not persisted. History retains the latest 20 runs per project.
Compare only equivalent configurations and correlate results with server CPU,
memory, database, queue and upstream telemetry. This is not proof of production
capacity or DDoS resistance.

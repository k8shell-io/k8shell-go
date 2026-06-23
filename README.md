# k8shell-go

Go SDK for the [k8shell](https://github.com/k8shell-io) API.

## Installation

```sh
go get github.com/k8shell-io/k8shell-go
```

## Usage

```go
import "github.com/k8shell-io/k8shell-go"

c := k8shell.New("https://k8shell.example.com", token)

// List workspaces
workspaces, err := c.ListWorkspaces(ctx, "", false)

// Create a workspace from a blueprint
resp, err := c.CreateWorkspace(ctx, k8shell.WorkspaceCreateRequest{
    Username:  "alice",
    Blueprint: "go-dev",
})

// Stream creation progress (SSE)
stream, err := c.MonitorWorkspace(ctx, resp.MonitorURL)
defer stream.Close()
```

## Client options

| Option | Description |
|---|---|
| `WithDebug()` | Log request/response headers to stderr |
| `WithDebugWriter(w)` | Log to a custom `io.Writer` (implies `WithDebug`) |
| `WithInsecure()` | Skip TLS certificate verification |

## Browser login flow

Use `NewAnonymous` to acquire a PAT without a pre-existing token:

```go
anon := k8shell.NewAnonymous("https://k8shell.example.com")

providers, err := anon.ListProviders(ctx)
// redirect user to the provider login URL, then poll:
for {
    token, err := anon.PollToken(ctx, oauthState)
    if err != nil { /* handle */ }
    if token != nil {
        c := k8shell.New("https://k8shell.example.com", token.Token)
        break
    }
    time.Sleep(2 * time.Second)
}
```

## Error handling

Non-2xx responses return `*APIError` with the HTTP status code and an optional
message from the response body:

```go
var apiErr *k8shell.APIError
if errors.As(err, &apiErr) {
    fmt.Println(apiErr.StatusCode, apiErr.Message)
}
```

## API reference

| Method | Description |
|---|---|
| `ListProviders(ctx)` | Identity providers that support browser login |
| `PollToken(ctx, state)` | Poll for a PAT after browser login |
| `GetProfile(ctx)` | Authenticated user's profile |
| `ListUsers(ctx)` | All users visible to the token |
| `ListSessions(ctx, username, all)` | SSH sessions for a user |
| `ListWorkspaces(ctx, username, all)` | Workspaces visible to the token |
| `CreateWorkspace(ctx, req)` | Submit a workspace creation request |
| `GetWorkspace(ctx, name)` | Workspace details by name |
| `DeleteWorkspace(ctx, name, deleteData)` | Stop (and optionally delete) a workspace |
| `MonitorWorkspace(ctx, monitorURL)` | Open SSE stream for a workspace job |

## License

AGPL-3.0-only

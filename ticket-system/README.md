# Ticket System (Golang Backend Intern Assignment)

A small backend service where a user can register, log in, create tickets,
view only their own tickets, and update the status of their own tickets.

## Tech notes

- **Language:** Go 1.22, standard library only (no external Go modules).
  - Routing uses Go 1.22's built-in `net/http` method+path patterns
    (e.g. `mux.HandleFunc("GET /tickets/{id}", ...)`), so no third-party
    router is needed.
  - JWT (HS256) is implemented directly on top of `crypto/hmac` and
    `crypto/sha256`.
  - Passwords are hashed with PBKDF2-HMAC-SHA256 (100,000 iterations,
    random 16-byte salt per user), implemented on top of `crypto/hmac`.
    Plaintext passwords are never stored.
- **Storage:** in-memory, guarded by a `sync.RWMutex`. Restarting the
  service clears all data (see Assumptions below).

## Project structure

```
main.go                              # wiring: routes, server startup
internal/
  models/models.go                   # User, Ticket, status transition rules
  store/store.go                     # thread-safe in-memory storage
  auth/password.go                   # PBKDF2 password hashing
  auth/jwt.go                        # manual HS256 JWT issue/verify
  middleware/auth_middleware.go      # Bearer token auth middleware
  handlers/auth_handler.go           # /auth/register, /auth/login
  handlers/ticket_handler.go         # /tickets, /tickets/{id}, status update
```

## Local run

```bash
go run .
```

Or build a binary:

```bash
go build -o ticket-system .
./ticket-system
```

The server listens on port `8080` (override with `PORT`). Set `JWT_SECRET`
to a real secret — a random string. Reference `.env.example` for the
environment variables the service reads.

Ubuntu/Debian without Go installed:

```bash
sudo apt-get update && sudo apt-get install -y golang-go
```

## Docker run (contract from the assignment)

```bash
docker build -t ticket-system .
docker run -p 8080:8080 -e JWT_SECRET=some-long-random-secret ticket-system
curl http://localhost:8080/health
```

Expected response:

```json
{"status": "ok"}
```

## API reference

| Method | Endpoint                 | Auth required | Purpose                       |
|--------|---------------------------|:---:|--------------------------------|
| GET    | `/health`                 | no  | Health check                   |
| POST   | `/auth/register`          | no  | Register a user                |
| POST   | `/auth/login`             | no  | Log in, returns a JWT          |
| POST   | `/tickets`                | yes | Create a ticket                |
| GET    | `/tickets`                | yes | List the caller's own tickets  |
| GET    | `/tickets/{id}`           | yes | Get one of the caller's own tickets |
| PATCH  | `/tickets/{id}/status`    | yes | Update status of an owned ticket |

Protected routes require `Authorization: Bearer <token>`.

### Example requests

```bash
# Register
curl -X POST http://localhost:8080/auth/register \
  -d '{"email":"alice@example.com","password":"password123"}'

# Login
curl -X POST http://localhost:8080/auth/login \
  -d '{"email":"alice@example.com","password":"password123"}'
# -> {"token": "..."}

TOKEN="paste token here"

# Create a ticket
curl -X POST http://localhost:8080/tickets \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"title":"Printer broken","description":"3rd floor printer jammed"}'

# List my tickets
curl http://localhost:8080/tickets -H "Authorization: Bearer $TOKEN"

# Update status
curl -X PATCH http://localhost:8080/tickets/<id>/status \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"status":"in_progress"}'
```

### Status flow

```
open -> in_progress -> closed
```

A closed ticket cannot move back to `open` or `in_progress`. Any illegal
transition returns `409 Conflict`. An unrecognized status value returns
`400 Bad Request`.

### Ownership

Accessing or updating a ticket ID that exists but belongs to another user
returns `404 Not Found` (not `403`), so a caller can't distinguish "doesn't
exist" from "exists but isn't yours."

## Assumptions

- Storage is in-memory; data does not persist across restarts. The
  assignment explicitly allows this for simplicity.
- Email is treated case-insensitively and normalized to lowercase on
  register/login.
- Passwords must be at least 8 characters.
- JWTs are valid for 24 hours.
- No admin role, ticket assignment, or comments — out of scope per the brief.

## Deployment

Deployed URL: `<fill in after deploying>`
Health check: `<deployed-url>/health`

Any Docker-friendly free-tier host works (e.g. Render, Railway, Fly.io).
See the deployment guide provided alongside this project for exact steps.

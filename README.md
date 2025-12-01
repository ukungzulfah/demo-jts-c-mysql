# JTS-C Demo with MySQL

A complete demo project showcasing **JTS Profile C (JTS-C)** authentication with MySQL session storage using Express.js.

## What is JTS?

**JTS (Janus Token System)** is a modern authentication protocol designed for secure, stateful session management. Profile C (JTS-C) provides:

- 🔐 **BearerPass** - Short-lived access tokens (signed JWT)
- 🔄 **StateProof** - Secure refresh tokens for session renewal
- 📱 **Multi-device session management**
- 🗄️ **Persistent session storage** with MySQL

## Features

- ✅ User authentication (login/logout)
- ✅ Token verification
- ✅ Token renewal using StateProof
- ✅ Multi-session support per user
- ✅ Logout from all devices
- ✅ MySQL-backed session persistence
- ✅ Health check endpoint

## Prerequisites

- Node.js 18+
- MySQL 5.7+ or MariaDB 10.3+

## Installation

```bash
# Clone the repository
git clone https://github.com/nicostudio/demo-jts-c-mysql.git
cd demo-jts-c-mysql

# Install dependencies
npm install
```

## Database Setup

Create a MySQL database:

```sql
CREATE DATABASE jts_test;
```

The session table will be created automatically on first run.

## Configuration

Update the MySQL connection in `src/server.ts` if needed:

```typescript
const pool = mysql.createPool({
  host: 'localhost',
  port: 3306,
  user: 'root',
  password: '',
  database: 'jts_test',
});
```

## Running the Server

```bash
# Development mode (with hot reload)
npm run dev

# Production mode
npm start
```

Server will start at `http://localhost:3000`

## API Endpoints

| Method | Endpoint | Description | Body |
|--------|----------|-------------|------|
| GET | `/health` | Health check | - |
| POST | `/auth/login` | Login | `{ email, password }` |
| GET | `/auth/me` | Verify token | Header: `Authorization: Bearer <token>` |
| POST | `/auth/renew` | Renew token | `{ stateProof }` |
| POST | `/auth/logout` | Logout session | `{ stateProof }` |
| POST | `/auth/sessions` | List all sessions | `{ stateProof }` |
| POST | `/auth/logout-all` | Logout all sessions | `{ stateProof }` |

## Test User

```
Email: user@demo.com
Password: password123
```

## Usage Examples

### Login

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@demo.com","password":"password123"}'
```

Response:
```json
{
  "message": "Login successful",
  "user": { "id": "user-001", "email": "user@demo.com", "name": "Demo User" },
  "bearerPass": "eyJhbGciOiJFUzI1NiIs...",
  "stateProof": "sp_xxxxx...",
  "expiresAt": "2025-12-01T10:00:00.000Z",
  "sessionId": "aid_xxxxx..."
}
```

### Verify Token

```bash
curl http://localhost:3000/auth/me \
  -H "Authorization: Bearer <bearerPass>"
```

### Renew Token

```bash
curl -X POST http://localhost:3000/auth/renew \
  -H "Content-Type: application/json" \
  -d '{"stateProof":"sp_xxxxx..."}'
```

### List Sessions

```bash
curl -X POST http://localhost:3000/auth/sessions \
  -H "Content-Type: application/json" \
  -d '{"stateProof":"sp_xxxxx..."}'
```

### Logout

```bash
curl -X POST http://localhost:3000/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"stateProof":"sp_xxxxx..."}'
```

### Logout All Sessions

```bash
curl -X POST http://localhost:3000/auth/logout-all \
  -H "Content-Type: application/json" \
  -d '{"stateProof":"sp_xxxxx..."}'
```

## Dependencies

- [@engjts/auth](https://www.npmjs.com/package/@engjts/auth) - JTS Authentication core library
- [@engjts/mysql-adapter](https://www.npmjs.com/package/@engjts/mysql-adapter) - MySQL session store adapter
- [express](https://expressjs.com/) - Web framework
- [mysql2](https://github.com/sidorares/node-mysql2) - MySQL client

## Project Structure

```
demo-jts-c-mysql/
├── src/
│   └── server.ts      # Main server with all endpoints
├── package.json
├── tsconfig.json
└── README.md
```

## How JTS-C Works

```
┌─────────────────────────────────────────────────────────────┐
│                     JTS-C Auth Flow                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. LOGIN                                                   │
│     Client ──credentials──► Server                          │
│     Client ◄──bearerPass + stateProof── Server              │
│                                                             │
│  2. API ACCESS                                              │
│     Client ──bearerPass──► Server (verify signature)        │
│     Client ◄──response── Server                             │
│                                                             │
│  3. TOKEN RENEWAL (when bearerPass expires)                 │
│     Client ──stateProof──► Server (validate session)        │
│     Client ◄──new bearerPass + stateProof── Server          │
│                                                             │
│  4. LOGOUT                                                  │
│     Client ──stateProof──► Server (invalidate session)      │
│     Client ◄──success── Server                              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## License

ISC

## Links

- [JTS Auth Library](https://www.npmjs.com/package/@engjts/auth)
- [MySQL Adapter](https://www.npmjs.com/package/@engjts/mysql-adapter)

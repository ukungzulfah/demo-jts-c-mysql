# JTS-C Demo with MySQL Adapter

A complete demo implementation of **JTS-C (Confidentiality Profile)** authentication system using Express.js and MySQL.

[![JTS Version](https://img.shields.io/badge/JTS-v1-blue.svg)](https://github.com/engjts)
[![Profile](https://img.shields.io/badge/Profile-JTS--C%2Fv1-green.svg)]()
[![MySQL](https://img.shields.io/badge/Database-MySQL-orange.svg)]()

## 🔐 What is JTS?

**Janus Token System (JTS)** is a modern authentication framework that combines stateless efficiency with stateful security. It addresses the limitations of traditional JWT-based authentication:

- ✅ **Instant Session Revocation** - Unlike pure JWTs, sessions can be invalidated immediately
- ✅ **Replay Attack Detection** - StateProof rotation detects and prevents token theft
- ✅ **Encrypted Tokens (JTS-C)** - Signed-then-Encrypted tokens for maximum confidentiality
- ✅ **CSRF Protection** - Built-in protection with HttpOnly cookies and header validation

### JTS Profiles

| Profile | Security Level | Use Case |
|---------|---------------|----------|
| JTS-L (Lite) | ⭐⭐ Basic | MVPs, Internal Tools |
| JTS-S (Standard) | ⭐⭐⭐⭐ High | Production Apps, Public APIs |
| **JTS-C (Confidentiality)** | ⭐⭐⭐⭐⭐ Maximum | Fintech, Healthcare, High-Security |

This demo implements **JTS-C**, the highest security profile with JWE encryption.

## 🚀 Quick Start

### Prerequisites

- Node.js >= 18.0.0
- MySQL >= 5.7 or MariaDB >= 10.2

### Installation

```bash
# Clone the repository
git clone https://github.com/ukungzulfah/demo-jts-c-mysql.git
cd demo-jts-c-mysql

# Install dependencies
npm install

# Create MySQL database
mysql -u root -e "CREATE DATABASE IF NOT EXISTS jts_test;"

# Start the server
npm run dev
```

### Configuration

Update the MySQL connection in `src/server.ts`:

```typescript
const pool = mysql.createPool({
  host: 'localhost',
  port: 3306,
  user: 'root',
  password: '',        // Your MySQL password
  database: 'jts_test',
});
```

## 📡 API Endpoints

### Discovery Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/.well-known/jts-configuration` | JTS server metadata |
| GET | `/.well-known/jts-jwks` | Public keys for token verification |

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/jts/login` | Authenticate and get tokens |
| POST | `/jts/renew` | Renew BearerPass (with StateProof rotation) |
| POST | `/jts/logout` | Terminate session |
| GET | `/jts/sessions` | List active sessions |
| DELETE | `/jts/sessions/:aid` | Revoke specific session |

### Protected API Endpoints

| Method | Endpoint | Required Permission |
|--------|----------|---------------------|
| GET | `/api/profile` | Authentication only |
| GET | `/api/posts` | `read:profile` |
| POST | `/api/posts` | `write:posts` |

## 🔑 Usage Examples

### Login

```bash
curl -X POST http://localhost:3000/jts/login \
  -H "Content-Type: application/json" \
  -H "X-JTS-Request: 1" \
  -c cookies.txt \
  -d '{"email":"user@demo.com","password":"password123"}'
```

**Response:**
```json
{
  "bearerPass": "eyJhbGciOiJSU0EtT0FFUC0yNTYi...",
  "expiresAt": 1764640351,
  "sessionId": "aid_ij8F47OgJY..."
}
```

### Access Protected Resource

```bash
curl http://localhost:3000/api/profile \
  -H "Authorization: Bearer <bearerPass>"
```

### Renew Token

```bash
curl -X POST http://localhost:3000/jts/renew \
  -H "X-JTS-Request: 1" \
  -b cookies.txt \
  -c cookies.txt
```

### Logout

```bash
curl -X POST http://localhost:3000/jts/logout \
  -H "X-JTS-Request: 1" \
  -b cookies.txt
```

## 🛡️ Security Features

### JWE Token Structure (JTS-C)

```json
{
  "alg": "RSA-OAEP-256",
  "enc": "A256GCM",
  "typ": "JTS-C/v1",
  "kid": "resource-server-key-2025-001"
}
```

The BearerPass is a **JWE (JSON Web Encryption)** token:
- Inner JWS signed with ES256
- Encrypted with RSA-OAEP-256 + A256GCM
- Only the Resource Server can decrypt

### StateProof Rotation

Every `/renew` request rotates the StateProof:

```
Before: SP_v1 (current), NULL (previous), version=1
After:  SP_v2 (current), SP_v1 (previous), version=2
```

### Grace Window (Concurrent Tabs)

A 10-second grace window allows concurrent requests from multiple browser tabs:

```
Tab A: /renew with SP_v1 → Success, returns SP_v2
Tab B: /renew with SP_v1 (within 10s) → Success, returns same SP_v2
```

### Replay Attack Detection

Using an old StateProof after the grace window triggers security:

```json
{
  "error": "session_compromised",
  "error_code": "JTS-401-05",
  "message": "Session compromised - replay attack detected",
  "action": "reauth"
}
```

**Result:** All sessions for the user are immediately revoked.

## 📊 Database Schema

The MySQL adapter automatically creates:

```sql
CREATE TABLE jts_sessions (
  aid VARCHAR(64) PRIMARY KEY,
  prn VARCHAR(256) NOT NULL,
  current_state_proof VARCHAR(256) NOT NULL,
  previous_state_proof VARCHAR(256),
  state_proof_version INT DEFAULT 1,
  rotation_timestamp DATETIME(3),
  device_fingerprint VARCHAR(128),
  created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
  expires_at DATETIME(3) NOT NULL,
  last_active DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
  user_agent TEXT,
  ip_address VARCHAR(45),
  metadata JSON
);
```

## 🧪 Testing

See [TEST_REPORT.md](./TEST_REPORT.md) for comprehensive test results.

### Quick Test

```bash
# Health check
curl http://localhost:3000/health

# Full test suite
npm test
```

## 📦 Dependencies

| Package | Description |
|---------|-------------|
| [@engjts/auth](https://www.npmjs.com/package/@engjts/auth) | JTS Authentication Library |
| [@engjts/mysql-adapter](https://www.npmjs.com/package/@engjts/mysql-adapter) | MySQL Session Store |
| express | Web Framework |
| mysql2 | MySQL Driver |
| cookie-parser | Cookie Parsing Middleware |

## 📚 JTS Specification

This implementation follows the [JTS Specification v1](https://github.com/engjts/jts-spec), including:

- Section 4.3: Cookie Requirements and CSRF Protection
- Section 4.4: StateProof Rotation
- Section 4.5: Rotation Grace Window
- Section 6: JTS-C (Confidentiality) Profile
- Section 7.2: Standard Error Codes

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

ISC

## 🔗 Related Projects

- [@engjts/auth](https://www.npmjs.com/package/@engjts/auth) - NPM Janus Token System (JTS)
- [@engjts/mysql-adapter](https://www.npmjs.com/package/@engjts/mysql-adapter) - NPM MySQL session store adapter
- [jts-core](https://github.com/ukungzulfah/jts-core) - JTS Core Library
- [engjts-mysql-adapter](https://github.com/ukungzulfah/engjts-mysql-adapter) - MySQL Adapter
- [demo-jts-s](https://github.com/ukungzulfah/jts-express-example) - JTS-S Demo (Standard Profile)

---

**Test Credentials:**
- Email: `user@demo.com`
- Password: `password123`

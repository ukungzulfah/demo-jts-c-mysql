/**
 * Demo: JTS-C Auth Server dengan MySQL Adapter
 * Implementasi JTS-C (Confidentiality) profile dengan enkripsi JWE
 *
 * JTS-C Features:
 * - Signed-then-Encrypted tokens (JWS wrapped in JWE)
 * - HttpOnly cookie untuk StateProof
 * - CSRF protection
 * - StateProof rotation
 */

import express, { Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import mysql from 'mysql2/promise';
import {
  JTSAuthServer,
  JTSResourceServer,
  generateKeyPair,
  generateRSAKeyPair,
  JTS_PROFILES,
  JTSAlgorithm,
  mountJTSRoutes,
  jtsAuth,
  jtsRequirePermissions,
  type LoginOptions,
  type StateProofCookieOptions,
} from '@engjts/auth';
import { MySQLSessionStore } from '@engjts/mysql-adapter';

const app = express();
app.use(express.json());
app.use(cookieParser());

// ============== CONFIGURATION ==============

// Simulated user database
const users: Record<string, { id: string; email: string; password: string; name: string }> = {
  'user@demo.com': {
    id: 'user-001',
    email: 'user@demo.com',
    password: 'password123',
    name: 'Demo User',
  },
};

// Cookie options sesuai JTS Spec Section 4.3
const cookieOptions: StateProofCookieOptions = {
  name: 'jts_state_proof',
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  path: '/jts',
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 hari
};

let authServer: JTSAuthServer;
let resourceServer: JTSResourceServer;
let sessionStore: MySQLSessionStore;

async function initAuth() {
  // Create MySQL pool
  const pool = mysql.createPool({
    host: 'localhost',
    port: 3306,
    user: 'root',
    password: '',
    database: 'jts_test',
  });

  // Create session store
  sessionStore = new MySQLSessionStore({ pool });
  await sessionStore.initialize();

  // Generate signing key pair (ES256 - ECDSA dengan P-256)
  const signingKey = await generateKeyPair('auth-server-key-2025-001', JTSAlgorithm.ES256);

  // Generate encryption key pair untuk JTS-C (RSA untuk JWE)
  const encryptionKey = await generateRSAKeyPair('resource-server-key-2025-001');

  // Create JTS Auth Server dengan profile JTS-C
  authServer = new JTSAuthServer({
    profile: JTS_PROFILES.CONFIDENTIAL, // 'JTS-C/v1'
    signingKey,
    sessionStore,
    // JTS-C specific: encryption key untuk JWE
    encryptionKey,
    bearerPassLifetime: 300, // 5 menit
    stateProofLifetime: 604800, // 7 hari
    gracePeriod: 30, // 30 detik grace period
    rotationGraceWindow: 10, // 10 detik grace window
    issuer: 'http://localhost:3000',
    audience: 'http://localhost:3000/api',
  });

  // Create Resource Server untuk verify encrypted tokens
  resourceServer = new JTSResourceServer({
    acceptedProfiles: [JTS_PROFILES.CONFIDENTIAL],
    // For signature verification - use Auth Server's public key
    publicKeys: [
      {
        kid: signingKey.kid,
        publicKey: signingKey.publicKey,
        algorithm: JTSAlgorithm.ES256,
      },
    ],
    // For JWE decryption - use Resource Server's private key
    decryptionKey: {
      kid: encryptionKey.kid,
      privateKey: encryptionKey.privateKey!,
    },
    audience: 'http://localhost:3000/api',
    gracePeriodTolerance: 30, // 30 detik grace period untuk in-flight requests
  });

  console.log('✅ JTS-C Auth Server initialized with MySQL adapter');
  console.log('   Profile: JTS-C/v1 (Confidentiality)');
  console.log('   Signing Algorithm: ES256');
  console.log('   Encryption: RSA-OAEP + A256GCM');

  // Setup routes after initialization
  setupRoutes();
}

function setupRoutes() {
  // Health check
  app.get('/health', async (_req: Request, res: Response) => {
    const dbHealthy = await sessionStore.healthCheck();
    res.json({
      status: 'ok',
      profile: 'JTS-C/v1',
      database: dbHealthy ? 'connected' : 'disconnected',
      timestamp: new Date().toISOString(),
    });
  });

  // Mount JTS routes menggunakan helper dari @engjts/auth
  // Ini akan otomatis membuat:
  // - POST /jts/login
  // - POST /jts/renew
  // - POST /jts/logout
  // - GET /jts/sessions
  // - DELETE /jts/sessions/:aid
  // - GET /.well-known/jts-jwks
  // - GET /.well-known/jts-configuration
  mountJTSRoutes(app, {
    authServer,
    resourceServer,
    cookieOptions,
    basePath: '/jts',

    // Credential validation function
    validateCredentials: async (req: Request): Promise<LoginOptions | null> => {
      const { email, password } = req.body;

      const user = users[email];
      if (!user || user.password !== password) {
        return null; // Invalid credentials
      }

      // Return LoginOptions untuk user yang valid
      return {
        prn: `user:${user.id}`,
        deviceFingerprint: req.headers['user-agent'] || 'unknown',
        userAgent: req.headers['user-agent'] as string,
        ipAddress: req.ip || '127.0.0.1',
        metadata: { email: user.email, name: user.name },
        // Extended claims untuk JTS-C
        audience: 'http://localhost:3000/api',
        permissions: ['read:profile', 'write:posts'],
        authMethod: 'pwd',
      };
    },

    // CSRF validation - check X-JTS-Request header atau Origin
    validateCSRF: (req: Request): boolean => {
      const jtsHeader = req.headers['x-jts-request'];
      if (jtsHeader === '1') return true;

      const origin = req.headers.origin || req.headers.referer;
      const allowedOrigins = ['http://localhost:3000', 'http://localhost:5173'];

      return !!origin && allowedOrigins.some((allowed) => origin.startsWith(allowed));
    },
  });

  // ============== PROTECTED API ROUTES ==============

  // Protected route example - requires authentication
  app.get('/api/profile', jtsAuth({ resourceServer }), (req: Request, res: Response) => {
    // req.jts contains verified payload
    res.json({
      message: 'Protected resource accessed successfully',
      user: {
        prn: req.jts?.payload.prn,
        permissions: req.jts?.payload.perm,
      },
      tokenType: 'JTS-C/v1 (encrypted)',
    });
  });

  // Protected route with specific permissions
  app.get(
    '/api/posts',
    jtsAuth({ resourceServer }),
    jtsRequirePermissions({ required: ['read:profile'] }),
    (req: Request, res: Response) => {
      res.json({
        message: 'Posts retrieved successfully',
        user: req.jts?.payload.prn,
        posts: [
          { id: 1, title: 'First Post' },
          { id: 2, title: 'Second Post' },
        ],
      });
    }
  );

  // Route requiring write permission
  app.post(
    '/api/posts',
    jtsAuth({ resourceServer }),
    jtsRequirePermissions({ required: ['write:posts'] }),
    (req: Request, res: Response) => {
      res.json({
        message: 'Post created successfully',
        user: req.jts?.payload.prn,
        post: { id: 3, ...req.body },
      });
    }
  );
}

// ============== START SERVER ==============

const PORT = 3000;

initAuth()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`
╔════════════════════════════════════════════════════════════════╗
║        🔐 JTS-C Demo Server (Confidentiality Profile)          ║
╠════════════════════════════════════════════════════════════════╣
║  Server running at: http://localhost:${PORT}                      ║
║  Profile: JTS-C/v1 (Signed-then-Encrypted)                     ║
╠════════════════════════════════════════════════════════════════╣
║  Discovery Endpoints:                                          ║
║    GET  /.well-known/jts-configuration                         ║
║    GET  /.well-known/jts-jwks                                  ║
╠════════════════════════════════════════════════════════════════╣
║  Auth Endpoints (auto-mounted via mountJTSRoutes):             ║
║    POST   /jts/login         - Login {email, password}         ║
║    POST   /jts/renew         - Renew (StateProof in cookie)    ║
║    POST   /jts/logout        - Logout (StateProof in cookie)   ║
║    GET    /jts/sessions      - List sessions (Bearer token)    ║
║    DELETE /jts/sessions/:aid - Revoke session                  ║
╠════════════════════════════════════════════════════════════════╣
║  Protected API Endpoints:                                      ║
║    GET  /api/profile   - Requires authentication               ║
║    GET  /api/posts     - Requires read:profile permission      ║
║    POST /api/posts     - Requires write:posts permission       ║
╠════════════════════════════════════════════════════════════════╣
║  Security Features:                                            ║
║    ✅ JWE Encryption (signed-then-encrypted)                   ║
║    ✅ HttpOnly Cookie for StateProof                           ║
║    ✅ CSRF Protection (Origin + X-JTS-Request header)          ║
║    ✅ StateProof Rotation on /renew                            ║
║    ✅ Replay Attack Detection                                  ║
║    ✅ Permission-based Access Control                          ║
║    ✅ Standard JTS Error Codes                                 ║
╠════════════════════════════════════════════════════════════════╣
║  Test:                                                         ║
║    Email: user@demo.com | Password: password123                ║
║                                                                ║
║  Note: For /jts/renew and /jts/logout, include header:         ║
║    X-JTS-Request: 1                                            ║
╚════════════════════════════════════════════════════════════════╝
    `);
    });
  })
  .catch((err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });

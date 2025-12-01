/**
 * Demo: JTS Auth Server dengan MySQL Adapter
 * Simple Express server untuk test authentication flow
 */

import express, { Request, Response } from 'express';
import mysql from 'mysql2/promise';
import { JTSAuthServer, generateKeyPair } from '@engjts/auth';
import { MySQLSessionStore } from '@engjts/mysql-adapter';

const app = express();
app.use(express.json());

// Simulated user database
const users: Record<string, { id: string; email: string; password: string; name: string }> = {
  'user@demo.com': {
    id: 'user-001',
    email: 'user@demo.com',
    password: 'password123',
    name: 'Demo User',
  },
};

let authServer: JTSAuthServer;
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
  const signingKey = await generateKeyPair('demo-key-001', 'ES256');

  // Create JTS Auth Server
  authServer = new JTSAuthServer({
    profile: 'JTS-S/v1',
    signingKey,
    sessionStore,
  });

  console.log('✅ JTS Auth Server initialized with MySQL adapter');
}

// ============== ROUTES ==============

// Health check
app.get('/health', async (_req: Request, res: Response) => {
  const dbHealthy = await sessionStore.healthCheck();
  res.json({ 
    status: 'ok', 
    database: dbHealthy ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString(),
  });
});

// Login
app.post('/auth/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    // Validate user
    const user = users[email];
    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create JTS session using login()
    const result = await authServer.login({
      prn: `user:${user.id}`,
      deviceFingerprint: req.headers['user-agent'] || 'unknown',
      userAgent: req.headers['user-agent'] as string,
      ipAddress: req.ip || '127.0.0.1',
      metadata: { email: user.email, name: user.name },
    });

    console.log(`✅ Login successful: ${user.email}`);

    res.json({
      message: 'Login successful',
      user: { id: user.id, email: user.email, name: user.name },
      bearerPass: result.bearerPass,
      stateProof: result.stateProof,
      expiresAt: new Date(result.expiresAt * 1000).toISOString(),
      sessionId: result.sessionId,
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed', details: String(error) });
  }
});

// Verify BearerPass (protected route example)
app.get('/auth/me', async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.substring(7);
    const result = authServer.verifyBearerPass(token);

    if (!result.valid) {
      return res.status(401).json({ error: result.error || 'Invalid token' });
    }

    res.json({
      valid: true,
      payload: result.payload,
    });
  } catch (error) {
    console.error('Verify error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Renew token using StateProof
app.post('/auth/renew', async (req: Request, res: Response) => {
  try {
    const { stateProof } = req.body;
    if (!stateProof) {
      return res.status(400).json({ error: 'stateProof required' });
    }

    const result = await authServer.renew({ stateProof });

    console.log(`🔄 Token renewed`);

    res.json({
      message: 'Token renewed',
      bearerPass: result.bearerPass,
      stateProof: result.stateProof,
      expiresAt: new Date(result.expiresAt * 1000).toISOString(),
    });
  } catch (error) {
    console.error('Renew error:', error);
    res.status(500).json({ error: 'Renewal failed', details: String(error) });
  }
});

// Logout using StateProof
app.post('/auth/logout', async (req: Request, res: Response) => {
  try {
    const { stateProof } = req.body;
    if (!stateProof) {
      return res.status(400).json({ error: 'stateProof required' });
    }

    const success = await authServer.logout(stateProof);

    console.log('👋 Logout successful');

    res.json({ message: 'Logged out successfully', success });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Get all sessions for user (using StateProof to identify user)
app.post('/auth/sessions', async (req: Request, res: Response) => {
  try {
    const { stateProof } = req.body;
    if (!stateProof) {
      return res.status(400).json({ error: 'stateProof required' });
    }

    // Validate stateProof first
    const validation = await sessionStore.getSessionByStateProof(stateProof);
    if (!validation.valid || !validation.session) {
      return res.status(401).json({ error: 'Invalid stateProof' });
    }

    const sessions = await sessionStore.getSessionsForPrincipal(validation.session.prn);

    res.json({
      count: sessions.length,
      sessions: sessions.map((s) => ({
        aid: s.aid,
        deviceFingerprint: s.deviceFingerprint,
        createdAt: s.createdAt,
        lastActive: s.lastActive,
        isCurrent: s.aid === validation.session!.aid,
      })),
    });
  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({ error: 'Failed to get sessions' });
  }
});

// Logout all sessions
app.post('/auth/logout-all', async (req: Request, res: Response) => {
  try {
    const { stateProof } = req.body;
    if (!stateProof) {
      return res.status(400).json({ error: 'stateProof required' });
    }

    const validation = await sessionStore.getSessionByStateProof(stateProof);
    if (!validation.valid || !validation.session) {
      return res.status(401).json({ error: 'Invalid stateProof' });
    }

    const count = await sessionStore.deleteAllSessionsForPrincipal(validation.session.prn);

    console.log(`🗑️ Logged out all sessions: ${count} deleted`);

    res.json({ 
      message: 'All sessions logged out',
      deletedCount: count,
    });
  } catch (error) {
    console.error('Logout all error:', error);
    res.status(500).json({ error: 'Logout all failed' });
  }
});

// ============== START SERVER ==============

const PORT = 3000;

initAuth().then(() => {
  app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════════════════╗
║           🚀 JTS Demo Server with MySQL Adapter            ║
╠════════════════════════════════════════════════════════════╣
║  Server running at: http://localhost:${PORT}                  ║
╠════════════════════════════════════════════════════════════╣
║  Endpoints:                                                ║
║    GET  /health          - Health check                    ║
║    POST /auth/login      - Login {email, password}         ║
║    GET  /auth/me         - Verify (Bearer token header)    ║
║    POST /auth/renew      - Renew {stateProof}              ║
║    POST /auth/logout     - Logout {stateProof}             ║
║    POST /auth/sessions   - List sessions {stateProof}      ║
║    POST /auth/logout-all - Logout all {stateProof}         ║
╠════════════════════════════════════════════════════════════╣
║  Test user: user@demo.com / password123                    ║
╚════════════════════════════════════════════════════════════╝
    `);
  });
}).catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

/**
 * WebSocket Authentication Test Script
 * Tests various token scenarios to debug JWT issues
 * 
 * Run: node scripts/test-websocket-auth.js
 */
const io = require('socket.io-client');
const jwt = require('jsonwebtoken');
const env = require('../src/config/env');

const SERVER_URL = process.env.WS_URL || 'http://localhost:3001';
const JWT_SECRET = env.jwtSecret;

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function testConnection(name, token, expectSuccess = true) {
  return new Promise((resolve) => {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`TEST: ${name}`);
    console.log(`Token preview: ${token?.substring(0, 50)}...`);
    console.log(`Expect success: ${expectSuccess}`);
    console.log(`${'='.repeat(60)}`);

    const socket = io(SERVER_URL, {
      auth: { token },
      reconnection: false,
      timeout: 5000
    });

    let connected = false;

    socket.on('connect', () => {
      console.log(`✅ CONNECTED: Socket ${socket.id}`);
      connected = true;
      socket.disconnect();
      resolve({ name, success: true, reason: 'Connected successfully' });
    });

    socket.on('connect_error', (error) => {
      console.log(`❌ CONNECTION ERROR: ${error.message}`);
      socket.disconnect();
      resolve({ name, success: false, reason: error.message });
    });

    socket.on('error', (error) => {
      console.log(`❌ ERROR: ${error}`);
      socket.disconnect();
      resolve({ name, success: false, reason: error });
    });

    // Timeout
    setTimeout(() => {
      if (!connected) {
        console.log(`❌ TIMEOUT: No response after 5s`);
        socket.disconnect();
        resolve({ name, success: false, reason: 'Timeout' });
      }
    }, 5000);
  });
}

async function main() {
  try {
    console.log(`\n🔐 WebSocket JWT Authentication Test Suite`);
    console.log(`Server: ${SERVER_URL}`);
    console.log(`JWT Secret: ${JWT_SECRET?.substring(0, 20)}...`);

    const results = [];

    // Test 1: No token
    console.log(`\n[1/5] Testing connection WITHOUT token...`);
    const test1 = await testConnection('No Token', undefined, false);
    results.push(test1);
    await sleep(500);

    // Test 2: Valid token
    console.log(`\n[2/5] Creating valid JWT token...`);
    const validToken = jwt.sign(
      {
        publicKey: 'TestUser123',
        sub: 'TestUser123'
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    console.log(`Valid token created: ${validToken.substring(0, 50)}...`);
    const test2 = await testConnection('Valid Token', validToken, true);
    results.push(test2);
    await sleep(500);

    // Test 3: Token with Bearer prefix (common issue)
    console.log(`\n[3/5] Testing token WITH "Bearer " prefix...`);
    const bearerToken = 'Bearer ' + validToken;
    const test3 = await testConnection('Bearer Prefixed Token', bearerToken, true);
    results.push(test3);
    await sleep(500);

    // Test 4: Expired token
    console.log(`\n[4/5] Creating EXPIRED token...`);
    const expiredToken = jwt.sign(
      { publicKey: 'TestUser456', sub: 'TestUser456' },
      JWT_SECRET,
      { expiresIn: '-1h' } // Expired 1 hour ago
    );
    console.log(`Expired token created: ${expiredToken.substring(0, 50)}...`);
    const test4 = await testConnection('Expired Token', expiredToken, false);
    results.push(test4);
    await sleep(500);

    // Test 5: Invalid token
    console.log(`\n[5/5] Testing INVALID/malformed token...`);
    const invalidToken = 'invalid.token.format';
    const test5 = await testConnection('Invalid Token', invalidToken, false);
    results.push(test5);
    await sleep(500);

    // Summary
    console.log(`\n${'='.repeat(60)}`);
    console.log(`📊 TEST SUMMARY`);
    console.log(`${'='.repeat(60)}`);

    const passed = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;

    results.forEach((result, idx) => {
      const icon = result.success ? '✅' : '❌';
      console.log(`${icon} [${idx + 1}] ${result.name}`);
      console.log(`    Reason: ${result.reason}`);
    });

    console.log(`${'='.repeat(60)}`);
    console.log(`Passed: ${passed}/5 | Failed: ${failed}/5`);
    console.log(`${'='.repeat(60)}\n`);

    // Check for issues
    console.log(`📋 ANALYSIS:`);
    
    if (results[1].success) {
      console.log(`✅ Valid token authentication works`);
    } else {
      console.log(`⚠️  Valid token failed - check JWT_SECRET and server`);
    }

    if (!results[0].success) {
      console.log(`✅ No token properly rejected`);
    } else {
      console.log(`⚠️  No token should be rejected`);
    }

    if (results[2].success) {
      console.log(`✅ Bearer prefix handling works (good!)`);
    } else {
      console.log(`⚠️  Bearer prefix handling failing - may be the issue`);
    }

    if (!results[3].success) {
      console.log(`✅ Expired token properly rejected`);
    } else {
      console.log(`⚠️  Expired token should be rejected`);
    }

    if (!results[4].success) {
      console.log(`✅ Invalid token properly rejected`);
    } else {
      console.log(`⚠️  Invalid token should be rejected`);
    }

    console.log(`\n`);
    process.exit(results[1].success ? 0 : 1);
  } catch (err) {
    console.error('❌ Test error:', err);
    process.exit(1);
  }
}

main();

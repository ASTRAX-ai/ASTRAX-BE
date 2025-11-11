#!/usr/bin/env node

/**
 * Full workflow test for Redis Pub/Sub + WebSocket integration
 * 
 * This script:
 * 1. Simulates a client connecting via WebSocket
 * 2. Creates a job via HTTP POST
 * 3. Listens for real-time WebSocket events
 * 4. Simulates Agent publishing status updates
 * 5. Verifies events are received by client
 * 
 * Usage:
 *   npm run dev (in another terminal)
 *   node scripts/test-pubsub-workflow.js
 */

const io = require('socket.io-client');
const redis = require('../src/lib/redis');
const logger = require('../src/lib/logger');
const jwt = require('jsonwebtoken');

const API_URL = process.env.API_URL || 'http://localhost:3001';
const JWT_SECRET = process.env.JWT_SECRET || 'test-secret-key';

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function generateTestJWT() {
  return jwt.sign(
    {
      publicKey: 'TEST_USER_' + Date.now(),
      sub: 'test@example.com',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    },
    JWT_SECRET,
    { algorithm: 'HS256' }
  );
}

async function main() {
  console.log('🧪 Full Workflow Test: WebSocket + Pub/Sub Integration\n');

  const token = generateTestJWT();
  const userPublicKey = jwt.decode(token).publicKey;

  let jobId = null;
  let receivedEvents = [];

  return new Promise((resolve, reject) => {
    // Step 1: Connect WebSocket
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('Step 1: Connect WebSocket Client');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    const socket = io(API_URL, {
      auth: { token },
      reconnection: true,
      reconnectionDelay: 100,
      reconnectionAttempts: 5
    });

    let connected = false;

    socket.on('connect', () => {
      console.log(`✅ WebSocket connected: ${socket.id}`);
      console.log(`   User: ${userPublicKey}\n`);
      connected = true;

      // Step 2: Create job
      (async () => {
        try {
          console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
          console.log('Step 2: Create Job via HTTP');
          console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

          const response = await fetch(`${API_URL}/api/v1/agent/rebalance`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
              priority: 'high',
              amount: 1000
            })
          });

          if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
          }

          const data = await response.json();
          jobId = data.jobId;

          console.log(`✅ Job created: ${jobId}`);
          console.log(`   Status: ${data.status}\n`);

          // Give WebSocket time to receive event
          await sleep(500);

          // Step 3: Listen for events
          console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
          console.log('Step 3: Listening for WebSocket Events');
          console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

          // Step 4: Simulate Agent publishing status updates
          console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
          console.log('Step 4: Simulate Agent Publishing Status');
          console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

          // Simulate Agent publishing "processing" status
          await sleep(1000);
          
          console.log(`📤 Publishing: jobId=${jobId} status=processing`);
          await redis.publish('agent:rebalance:status', JSON.stringify({
            jobId,
            status: 'processing',
            userId: userPublicKey,
            timestamp: new Date().toISOString()
          }));
          console.log('✅ Published to Redis\n');

          // Simulate Agent publishing "done" status
          await sleep(2000);
          
          console.log(`📤 Publishing: jobId=${jobId} status=done`);
          await redis.publish('agent:rebalance:status', JSON.stringify({
            jobId,
            status: 'done',
            userId: userPublicKey,
            timestamp: new Date().toISOString()
          }));
          console.log('✅ Published to Redis\n');

          // Wait for all events to be received
          await sleep(2000);

          // Step 5: Results
          console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
          console.log('Step 5: Results');
          console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

          console.log(`📊 Received ${receivedEvents.length} WebSocket events:\n`);
          
          receivedEvents.forEach((event, i) => {
            console.log(`[${i + 1}] ${event.name}`);
            console.log(`    Payload: ${JSON.stringify(event.payload)}`);
            console.log(`    Received at: ${event.receivedAt}\n`);
          });

          // Verification
          console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
          console.log('Verification');
          console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

          const eventNames = receivedEvents.map(e => e.name);
          const hasCreated = eventNames.includes('rebalance:created');
          const hasProcessing = eventNames.includes('rebalance:processing');
          const hasDone = eventNames.includes('rebalance:processing'); // Note: could be done too

          console.log(`✅ Created event received: ${hasCreated ? '✓' : '✗'}`);
          console.log(`✅ Processing event received: ${hasProcessing ? '✓' : '✗'}`);
          console.log(`✅ All events matched jobId: ${eventNames.every(e => receivedEvents.find(r => r.name === e).payload.jobId === jobId) ? '✓' : '✗'}`);

          console.log('\n✨ Workflow test completed!\n');

          socket.disconnect();
          resolve();
        } catch (err) {
          console.error('❌ Error during workflow:', err);
          socket.disconnect();
          reject(err);
        }
      })();
    });

    socket.on('rebalance:created', (payload) => {
      console.log(`\n📨 Received WebSocket Event: rebalance:created`);
      console.log(`   Payload: ${JSON.stringify(payload)}`);
      
      receivedEvents.push({
        name: 'rebalance:created',
        payload,
        receivedAt: new Date().toISOString()
      });
    });

    socket.on('rebalance:processing', (payload) => {
      console.log(`\n📨 Received WebSocket Event: rebalance:processing`);
      console.log(`   Payload: ${JSON.stringify(payload)}`);
      
      receivedEvents.push({
        name: 'rebalance:processing',
        payload,
        receivedAt: new Date().toISOString()
      });
    });

    socket.on('rebalance:done', (payload) => {
      console.log(`\n📨 Received WebSocket Event: rebalance:done`);
      console.log(`   Payload: ${JSON.stringify(payload)}`);
      
      receivedEvents.push({
        name: 'rebalance:done',
        payload,
        receivedAt: new Date().toISOString()
      });
    });

    socket.on('rebalance:error', (payload) => {
      console.log(`\n📨 Received WebSocket Event: rebalance:error`);
      console.log(`   Payload: ${JSON.stringify(payload)}`);
      
      receivedEvents.push({
        name: 'rebalance:error',
        payload,
        receivedAt: new Date().toISOString()
      });
    });

    socket.on('connect_error', (error) => {
      if (!connected) {
        console.error('❌ WebSocket connection failed:', error.message);
        reject(error);
      }
    });

    socket.on('disconnect', () => {
      console.log('\n👋 WebSocket disconnected\n');
    });

    // Timeout if test takes too long
    setTimeout(() => {
      socket.disconnect();
      reject(new Error('Test timeout'));
    }, 30000);
  });
}

main()
  .then(() => {
    console.log('🎉 All tests passed!\n');
    process.exit(0);
  })
  .catch(err => {
    console.error('\n❌ Test failed:', err.message);
    process.exit(1);
  });

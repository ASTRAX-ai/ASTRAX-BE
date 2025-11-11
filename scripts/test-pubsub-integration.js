#!/usr/bin/env node

/**
 * Test script for Redis Pub/Sub integration
 * 
 * This script simulates an Agent Service publishing status updates
 * to the Redis channel 'agent:rebalance:status'.
 * 
 * Usage:
 *   node scripts/test-pubsub-integration.js
 */

const redis = require('../src/lib/redis');
const logger = require('../src/lib/logger');

async function main() {
  console.log('🔧 Testing Redis Pub/Sub Integration\n');
  
  try {
    // Test data
    const testJobs = [
      {
        jobId: `1731304200000-a7f3e2k`,
        userId: 'GXHEXYVepv5EQnhq9VYVWkvW6QDMRj4QZA2B2mmKpCzq',
        statuses: ['processing', 'done']
      },
      {
        jobId: `1731304200001-b9f4e3l`,
        userId: 'QRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890',
        statuses: ['processing', 'processing', 'error']
      }
    ];

    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('Step 1: Queue Test Jobs');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    for (const job of testJobs) {
      await redis.rpush('agent:rebalance:jobs', job.jobId);
      console.log(`✅ Queued job: ${job.jobId}`);
    }

    // Verify queue
    const queueItems = await redis.lrange('agent:rebalance:jobs', 0, -1);
    console.log(`\n📋 Queue contents (${queueItems.length} items):`);
    queueItems.forEach((item, i) => {
      console.log(`   [${i + 1}] ${item}`);
    });

    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('Step 2: Publish Status Updates (Simulating Agent)');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    for (const job of testJobs) {
      console.log(`\n📤 Publishing updates for job: ${job.jobId}`);
      console.log(`   User: ${job.userId}\n`);

      for (let i = 0; i < job.statuses.length; i++) {
        const status = job.statuses[i];
        const message = {
          jobId: job.jobId,
          status: status,
          userId: job.userId,
          timestamp: new Date().toISOString(),
          details: `Status update ${i + 1}/${job.statuses.length}`
        };

        console.log(`   → Publishing: ${JSON.stringify(message)}`);
        
        await redis.publish('agent:rebalance:status', JSON.stringify(message));
        
        console.log(`   ✅ Published: ${status}`);

        // Small delay between updates
        if (i < job.statuses.length - 1) {
          await new Promise(r => setTimeout(r, 1000));
        }
      }
    }

    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('Step 3: Verify Backend Received Updates');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    console.log('✅ All test messages published!');
    console.log('\n📌 Next Steps:');
    console.log('   1. Check server logs for [Redis Subscribe] messages');
    console.log('   2. Watch for [rebalance:processing] events');
    console.log('   3. Verify WebSocket client receives updates\n');

    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('Expected Server Log Output:');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    console.log('[info] [Redis Subscribe] Subscribed to agent:rebalance:status (total: 1)');
    console.log('[info] [Redis Subscribe] Received status update: jobId=1731304200000-a7f3e2k status=processing user=GXHEXYVepv5...');
    console.log('[info] [rebalance:processing] jobId=1731304200000-a7f3e2k user=GXHEXYVepv5...');
    console.log('[info] [Redis Subscribe] Received status update: jobId=1731304200000-a7f3e2k status=done user=GXHEXYVepv5...');

    console.log('\n✨ Test completed successfully!\n');

    process.exit(0);
  } catch (err) {
    console.error('❌ Test failed:', err);
    process.exit(1);
  }
}

main();

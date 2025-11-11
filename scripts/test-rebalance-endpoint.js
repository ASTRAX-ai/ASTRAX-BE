/**
 * Quick test script to verify rebalance endpoints
 * Run: node scripts/test-rebalance-endpoint.js
 */
const redis = require('../src/lib/redis');
const http = require('http');

async function main() {
  try {
    console.log('[TEST] Setting up test data in Redis...');
    
    // Set a test job in Redis with TTL 1 hour
    const testJobId = `test-job-${Date.now()}`;
    const testJobData = {
      jobId: testJobId,
      status: 'created',
      user: 'TestUser123',
      createdAt: new Date().toISOString(),
      type: 'rebalance',
      detail: 'Test rebalance job'
    };
    
    await redis.set(`agent:rebalance:job:${testJobId}`, testJobData, 3600);
    console.log(`[TEST] ✓ Saved test job: ${testJobId}`);
    console.log(`[TEST] Job data:`, testJobData);
    
    // Retrieve the job to verify
    const retrieved = await redis.get(`agent:rebalance:job:${testJobId}`);
    console.log(`[TEST] ✓ Retrieved from Redis:`, retrieved);
    
    console.log('\n[TEST] Next: Call GET /api/v1/rebalance/' + testJobId);
    console.log('[TEST] Example curl command:');
    console.log(`  curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:3001/api/v1/rebalance/${testJobId}`);
    console.log('\n[TEST] OR use the test-rebalance-route.js if it has JWT testing');
    
    process.exit(0);
  } catch (err) {
    console.error('[TEST ERROR]', err);
    process.exit(1);
  }
}

main();

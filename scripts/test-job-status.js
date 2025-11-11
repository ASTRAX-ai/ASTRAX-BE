/**
 * Test script to demonstrate job status tracking
 * Shows the flow: create job → check status → simulate progress
 * 
 * Run: node scripts/test-job-status.js
 */
const redis = require('../src/lib/redis');
const jobStatus = require('../src/lib/jobStatus');

async function main() {
  try {
    console.log('===== Job Status Tracking Demo =====\n');
    
    // Demo 1: Create a job record
    console.log('1️⃣  Creating job record with initial status "created"...');
    const jobId = `demo-${Date.now()}`;
    const jobData = {
      payload: { action: 'rebalance', amount: 100 },
      type: 'rebalance',
      priority: 'high',
      requestMetadata: {
        clientIp: '192.168.1.1',
        userAgent: 'demo-client/1.0'
      }
    };
    
    const userPublicKey = 'GXHEXYVepv5EQnhq9VYVWkvW6QDMRj4QZA2B2mmKpCzq';
    const initialRecord = jobStatus.createJobRecord(jobId, jobData, userPublicKey);
    
    console.log('\n📋 Initial Job Record:');
    console.log(JSON.stringify(initialRecord, null, 2));
    
    // Save to Redis
    const jobKey = `agent:rebalance:job:${jobId}`;
    await redis.set(jobKey, initialRecord, 24 * 60 * 60);
    console.log(`\n✅ Saved to Redis key: ${jobKey}`);
    
    // Demo 2: Retrieve and format response
    console.log('\n2️⃣  Retrieving job via API (GET /api/v1/rebalance/:jobId)...');
    const retrieved = await jobStatus.getJob(jobId);
    const formatted = jobStatus.formatJobResponse(retrieved);
    
    console.log('\n📦 Formatted API Response:');
    console.log(JSON.stringify(formatted, null, 2));
    
    // Demo 3: Update status to 'processing'
    console.log('\n3️⃣  Updating job status to "processing"...');
    const processing = await jobStatus.updateJobStatus(jobId, jobStatus.JOB_STATUS.PROCESSING, 'Started processing on worker node 1');
    
    console.log('\n📊 Job after processing update:');
    console.log(JSON.stringify(processing, null, 2));
    
    // Demo 4: Update status to 'done'
    console.log('\n4️⃣  Updating job status to "done"...');
    const done = await jobStatus.updateJobStatus(jobId, jobStatus.JOB_STATUS.DONE, 'Rebalance completed successfully');
    
    console.log('\n✨ Job after completion:');
    console.log(JSON.stringify(done, null, 2));
    
    // Demo 5: Show status history
    console.log('\n5️⃣  Complete Status History:');
    done.statusHistory.forEach((entry, idx) => {
      console.log(`   [${idx + 1}] ${entry.status} @ ${entry.timestamp}`);
      console.log(`       → ${entry.message}`);
    });
    
    console.log('\n✅ Test completed successfully!');
    console.log(`\nYou can now call:`);
    console.log(`  curl -H "Authorization: Bearer YOUR_JWT" http://localhost:3001/api/v1/rebalance/${jobId}`);
    console.log(`\nThis will return the formatted job with full status history.`);
    
    process.exit(0);
  } catch (err) {
    console.error('❌ Test Error:', err);
    process.exit(1);
  }
}

main();

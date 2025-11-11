# Redis Pub/Sub Integration Guide

## Overview

Sistem backend sekarang terintegrasi dengan Redis Pub/Sub untuk real-time status updates dari Agent Service. Ketika Agent selesai memproses job, ia akan publish status update ke Redis channel, dan backend akan forward update tersebut ke client via WebSocket.

---

## Architecture Flow

```
┌──────────────┐
│   Frontend   │
│   (Client)   │
└──────┬───────┘
       │ WebSocket (rebalance:created)
       │ WebSocket (rebalance:processing)
       │
       ▼
┌─────────────────────────────────┐
│  Backend (Node.js)              │
│  ─────────────────────────────  │
│  1. POST /agent/rebalance       │
│     → LPUSH jobId to queue      │
│     → Emit 'rebalance:created'  │
│                                 │
│  2. Redis Pub/Sub Subscriber    │
│     ← Subscribe to channel      │
│     (agent:rebalance:status)    │
│     → Emit 'rebalance:processing'
└────────┬────────────────────────┘
         │
         │ Redis Channel
         │ (agent:rebalance:status)
         │
         ▼
┌──────────────────────┐
│  Agent Service       │
│  (External Worker)   │
│  ────────────────    │
│  1. BRPOP from queue │
│  2. Process job      │
│  3. PUBLISH to Redis │
│     { jobId, status, │
│       userId }       │
└──────────────────────┘
```

---

## Backend Implementation Details

### 1. LPUSH Job ID to Queue

**Location:** `src/api/agent/rebalance/rebalance.controller.js`

Ketika job berhasil dibuat, jobId di-push ke queue list:

```javascript
// LPUSH jobId to tracking queue (for agent to monitor)
const queueListKey = 'agent:rebalance:jobs';
await redis.rpush(queueListKey, jobId);
logger.info(`LPUSH jobId=${jobId} to queue=${queueListKey}`);
```

**Queue Details:**
- **Key:** `agent:rebalance:jobs`
- **Type:** Redis List
- **Operation:** RPUSH (append to right/tail)
- **Usage:** Agent pops from left (LPOP/BRPOP) untuk FIFO

**Example Flow:**
```
Request 1: jobId="1731304200000-a7f3e2k" → RPUSH → Queue: [a7f3e2k]
Request 2: jobId="1731304200001-b9f4e3l" → RPUSH → Queue: [a7f3e2k, b9f4e3l]
Agent: BRPOP → Gets "a7f3e2k" → Queue: [b9f4e3l]
```

---

### 2. Redis Pub/Sub Subscription

**Location:** `src/lib/gateway.js` → `_subscribeToStatusUpdates()` method

Backend membuat subscriber connection yang listen ke channel:

```javascript
async _subscribeToStatusUpdates() {
    const subscriber = ioredis.duplicate();
    
    subscriber.on('message', async (channel, message) => {
        // Parse agent's status update
        const { jobId, status, userId } = JSON.parse(message);
        
        // Emit to WebSocket client
        const room = `user:${userId}`;
        this.io.to(room).emit(REBALANCE_EVENTS.PROCESSING, { jobId, status });
    });
    
    await subscriber.subscribe('agent:rebalance:status');
}
```

**Channel Details:**
- **Channel Name:** `agent:rebalance:status`
- **Message Format:** JSON `{ jobId, status, userId }`
- **Connection:** Separate ioredis subscriber (independent from main client)
- **Lifecycle:** Maintained throughout server uptime

---

## Agent Service Integration

### Agent Publishing Status Updates

Agent service harus publish ke Redis channel dengan format yang tepat:

```javascript
// In Agent Service:
const message = {
    jobId: "1731304200000-a7f3e2k",
    status: "processing",  // or "done", "error"
    userId: "GXHEXYVepv5EQnhq9VYVWkvW6QDMRj4QZA2B2mmKpCzq"
};

await redis.publish('agent:rebalance:status', JSON.stringify(message));
```

**Message Fields:**
- `jobId` (string): Unique job identifier
- `status` (string): Current status ("processing", "done", "error")
- `userId` (string): Owner's public key (for routing to correct WebSocket room)

**Example Messages:**
```json
{
  "jobId": "1731304200000-a7f3e2k",
  "status": "processing",
  "userId": "GXHEXYVepv5EQnhq9VYVWkvW6QDMRj4QZA2B2mmKpCzq"
}
```

---

## Client Integration

### 1. Listen for Status Updates

```javascript
const socket = io('http://localhost:3001', {
    auth: { token: jwtToken }
});

// Listen for real-time status updates from Agent
socket.on('rebalance:processing', ({ jobId, status }) => {
    console.log(`Job ${jobId} is now ${status}`);
    updateUI(jobId, status);
});

// Handle other status events (when added)
socket.on('rebalance:done', ({ jobId, status }) => {
    console.log(`Job ${jobId} completed!`);
    showSuccess(jobId);
});

socket.on('rebalance:error', ({ jobId, status }) => {
    console.log(`Job ${jobId} failed!`);
    showError(jobId);
});
```

### 2. Complete Workflow

```javascript
class RebalanceManager {
    constructor(jwtToken) {
        this.jwtToken = jwtToken;
        this.socket = io('http://localhost:3001', {
            auth: { token: jwtToken }
        });
        
        this.setupListeners();
    }

    setupListeners() {
        // Job creation notification (delivered immediately)
        this.socket.on('rebalance:created', ({ jobId }) => {
            console.log('✅ Job created:', jobId);
            this.onJobCreated?.(jobId);
        });

        // Status update from Agent
        this.socket.on('rebalance:processing', ({ jobId, status }) => {
            console.log('⏳ Job processing:', jobId, status);
            this.onJobProcessing?.(jobId, status);
        });

        // Job completion
        this.socket.on('rebalance:done', ({ jobId, status }) => {
            console.log('✅ Job done:', jobId);
            this.onJobDone?.(jobId);
        });

        // Job error
        this.socket.on('rebalance:error', ({ jobId, status }) => {
            console.log('❌ Job error:', jobId);
            this.onJobError?.(jobId);
        });
    }

    async createAndMonitor(jobConfig) {
        // Step 1: Create job (returns jobId)
        const res = await fetch('http://localhost:3001/api/v1/agent/rebalance', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.jwtToken}`
            },
            body: JSON.stringify(jobConfig)
        });

        const { jobId } = await res.json();
        console.log('Job created:', jobId);

        // Step 2: Listen for WebSocket events (automatic)
        // Step 3: Optional - also poll status via HTTP
        // this.pollStatus(jobId);

        return jobId;
    }

    async pollStatus(jobId, maxWait = 120000) {
        const startTime = Date.now();
        
        while (Date.now() - startTime < maxWait) {
            const res = await fetch(`http://localhost:3001/api/v1/rebalance/${jobId}`, {
                headers: { 'Authorization': `Bearer ${this.jwtToken}` }
            });
            
            const job = await res.json();
            console.log('Status:', job.status);

            if (job.status === 'done' || job.status === 'error') {
                return job;
            }

            await new Promise(r => setTimeout(r, 2000));
        }
    }
}

// Usage:
const manager = new RebalanceManager(jwtToken);

manager.onJobCreated = (jobId) => {
    console.log('UI: Showing processing indicator for', jobId);
};

manager.onJobProcessing = (jobId, status) => {
    console.log('UI: Updating progress for', jobId, 'status:', status);
};

manager.onJobDone = (jobId) => {
    console.log('UI: Job complete!', jobId);
};

const jobId = await manager.createAndMonitor({
    priority: 'high',
    amount: 1000
});
```

---

## Real-Time Event Timeline

### Request Timeline

```
Time    Client                  Backend                 Agent
────────────────────────────────────────────────────────────────
T0      POST /agent/rebalance   
        ───────────────────────→
                                Create job record
                                LPUSH jobId to queue
                                Emit 'rebalance:created'
                                ←─────────────────────
        ✅ Receive 'rebalance:created' + jobId

T1                              [Waiting for Agent...]
                                (Redis Pub/Sub listening)

T2                                                      BRPOP queue
                                                        Get jobId
                                                        Start processing
                                                        PUBLISH to 'agent:rebalance:status'
                                                        { jobId, status: 'processing', userId }
                                                        ──────────────────────→

T3                              Receive via Pub/Sub
                                Emit 'rebalance:processing'
                                ←─────────────────────
        ✅ Receive 'rebalance:processing'

T4                                                      Processing...
                                                        Job complete
                                                        PUBLISH status: 'done'
                                                        ──────────────────────→

T5                              Emit 'rebalance:done'
                                ←─────────────────────
        ✅ Receive 'rebalance:done'
```

---

## Error Handling

### Agent Offline Scenario

Jika Agent offline saat job diciptakan:

1. ✅ Client terima `rebalance:created` (immediate)
2. ⏳ Client tidak terima `rebalance:processing` (Agent offline)
3. ✅ Client masih bisa polling via HTTP GET endpoint
4. ✅ Ketika Agent online, status updates akan diterima

### Agent Failure

Jika Agent error saat processing:

```javascript
// Agent publishes error status
{
    jobId: "1731304200000-a7f3e2k",
    status: "error",
    userId: "GXHEXYVepv5EQnhq9VYVWkvW6QDMRj4QZA2B2mmKpCzq",
    error: "Processing failed: insufficient balance"
}

// Backend emits to client
socket.on('rebalance:error', ({ jobId, status, error }) => {
    console.error('Job failed:', error);
});
```

---

## Monitoring & Debugging

### Server Logs - Successful Flow

```
[info] LPUSH jobId=1731304200000-a7f3e2k to queue=agent:rebalance:jobs
[info] [rebalance:created] jobId=1731304200000-a7f3e2k user=GXHEXYVepv5EQnhq9VYVWkvW6QDMRj4QZA2B2mmKpCzq sockets=1

[Redis Subscribe] Subscribed to agent:rebalance:status (total: 1)

[info] [Redis Subscribe] Received status update: jobId=1731304200000-a7f3e2k status=processing user=GXHEXYVepv5EQnhq9VYVWkvW6QDMRj4QZA2B2mmKpCzq
[info] [rebalance:processing] jobId=1731304200000-a7f3e2k user=GXHEXYVepv5EQnhq9VYVWkvW6QDMRj4QZA2B2mmKpCzq
```

### Verify Queue Items

```bash
# Check jobs in queue
redis-cli LRANGE agent:rebalance:jobs 0 -1

# Output:
# 1) "1731304200000-a7f3e2k"
# 2) "1731304200001-b9f4e3l"
```

### Monitor Pub/Sub

```bash
# In one terminal, subscribe to channel
redis-cli
> SUBSCRIBE agent:rebalance:status

# In another terminal, publish test message
redis-cli
> PUBLISH agent:rebalance:status '{"jobId":"test-123","status":"processing","userId":"test-user"}'
```

---

## Configuration

**No additional configuration needed!**

Backend automatically:
- ✅ Creates Redis subscriber on startup
- ✅ Subscribes to `agent:rebalance:status` channel
- ✅ Forwards all messages to connected WebSocket clients
- ✅ Routes messages to correct user rooms

---

## Event Types

Currently supported:
- `rebalance:created` - Job created and queued (emitted immediately)
- `rebalance:processing` - Job being processed by Agent (via Pub/Sub)
- `rebalance:done` - Job completed successfully (via Pub/Sub, when added)
- `rebalance:error` - Job failed (via Pub/Sub, when added)

Future events can be added by:
1. Adding constant to `REBALANCE_EVENTS` in `constants.js`
2. Handling new event type in `_subscribeToStatusUpdates()`
3. Updating client listeners

---

## Best Practices

1. **Always listen for `rebalance:created` first**
   - This is emitted immediately after POST
   - Shows job ID to user
   - Should update UI to show loading state

2. **Don't rely only on WebSocket for status**
   - Implement HTTP polling as fallback
   - Use both for redundancy

3. **Handle reconnections gracefully**
   - Client should auto-poll when offline
   - WebSocket will deliver pending events on reconnect

4. **Log important events in Agent**
   - Include error messages in `rebalance:error` event
   - Include processing details in `rebalance:processing`

5. **Set reasonable timeouts**
   - Don't wait forever for job completion
   - Implement 5-minute timeout as default
   - Let user manually check status after timeout

---

## Troubleshooting

**Issue:** Client not receiving `rebalance:processing` event
- ✅ Check Agent is publishing to correct channel: `agent:rebalance:status`
- ✅ Check message format is valid JSON with `jobId`, `status`, `userId`
- ✅ Check userId matches client's public key
- ✅ Check backend logs for Pub/Sub errors

**Issue:** Job ID not appearing in queue
- ✅ Check RPUSH is executing in rebalance.controller.js
- ✅ Run `redis-cli LRANGE agent:rebalance:jobs 0 -1` to verify
- ✅ Check Redis connection is working

**Issue:** Pub/Sub not connecting on startup
- ✅ Check ioredis client is initialized
- ✅ Check Redis is running and accessible
- ✅ Check server logs for `Failed to setup Redis status subscription`

---

## Summary

✅ Backend LPUSH jobId to queue after creation  
✅ Backend subscribes to `agent:rebalance:status` via Pub/Sub  
✅ Backend forwards Agent status updates to clients via WebSocket  
✅ Clients receive real-time status updates  
✅ Full integration with job status tracking  
✅ Fallback to HTTP polling always available  

**Architecture:** Frontend → WebSocket (Socket.IO) → Backend → Redis Pub/Sub ← Agent Service

**Last Updated:** November 11, 2025

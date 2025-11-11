const queue = require('../../../lib/queue');
const redis = require('../../../lib/redis');
const metrics = require('../../../lib/metrics');
const gateway = require('../../../lib/gateway');
const jobStatus = require('../../../lib/jobStatus');
const logger = require('../../../lib/logger');

// POST /api/agent/rebalance
// Body: { /* arbitrary payload for the agent to act on */ }
async function requestRebalance(req, res) {
  try {
    const user = req.user;
    if (!user) return res.status(401).json({ error: 'Unauthorized' });

    // Check rate limit (10 requests per minute per user)
    const rateLimited = !(await metrics.checkRateLimit(user._id, 10, 60));
    if (rateLimited) {
      return res.status(429).json({ error: 'Too many requests. Please wait before trying again.' });
    }

    const payload = req.body || {};
    const startTime = Date.now();
    const now = new Date().toISOString();

    // Prepare job payload (for queue)
    const queuePayload = {
      user: { publicKey: user.publicKey, id: user._id },
      payload,
      type: 'rebalance',
      priority: payload.priority || 'normal',
      requestMetadata: {
        clientIp: req.ip,
        userAgent: req.headers['user-agent'],
        timestamp: startTime
      }
    };

    const queueKey = 'agent:rebalance:request';
    const jobId = await queue.enqueue(queueKey, queuePayload);

    // Create job record with initial status = 'created'
    const jobRecord = jobStatus.createJobRecord(jobId, queuePayload, user.publicKey);
    
    // Persist job metadata to Redis (TTL 24h)
    const jobKey = `agent:rebalance:job:${jobId}`;
    await redis.set(jobKey, jobRecord, 24 * 60 * 60);

    // LPUSH jobId to tracking queue (for agent to monitor)
    const queueListKey = 'agent:rebalance:jobs';
    await redis.rpush(queueListKey, jobId);
    logger.info(`LPUSH jobId=${jobId} to queue=${queueListKey}`);

    // Record metrics
    await metrics.incrementCounter('jobs');
    await metrics.recordJobTiming(jobId, startTime);

    // Emit job creation event via WebSocket
    await gateway.emitJobCreated(jobId, user.publicKey);

    return res.status(202).json({ ok: true, jobId, status: jobStatus.JOB_STATUS.CREATED });
  } catch (err) {
    console.error('requestRebalance error', err);
    // Record failure
    const jobId = err.jobId || `error-${Date.now()}`;
    await metrics.recordFailedJob(jobId, err, req.body);
    return res.status(500).json({ error: 'internal' });
  }
}

/**
 * GET /api/agent/rebalance/metrics
 * Returns metrics summary for monitoring
 */
async function getMetrics(req, res) {
  try {
    const days = parseInt(req.query.days) || 7;
    const summary = await metrics.getMetricsSummary(days);
    return res.json(summary);
  } catch (err) {
    console.error('getMetrics error', err);
    return res.status(500).json({ error: 'Failed to fetch metrics' });
  }
}

module.exports = { 
  requestRebalance,
  getMetrics,
};

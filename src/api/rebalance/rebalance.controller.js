const redis = require('../../lib/redis');
const logger = require('../../lib/logger');
const jobStatus = require('../../lib/jobStatus');

/**
 * GET /api/v1/rebalance/:jobId
 * Returns job metadata/status fetched from Redis (Upstash)
 * Includes current status, status history, and timestamps
 */
async function getJobStatus(req, res) {
  try {
    const jobId = req.params.jobId;
    if (!jobId) return res.status(400).json({ error: 'jobId required' });

    // Try to get job record
    const jobRecord = await jobStatus.getJob(jobId);
    
    if (jobRecord) {
      // Format and return job data with status info
      const formatted = jobStatus.formatJobResponse(jobRecord);
      return res.json(formatted);
    }

    // If not found via getJob, try direct Redis GET calls as fallback
    const candidates = [
      `agent:rebalance:job:${jobId}`,
      `rebalance:job:${jobId}`,
      `job:rebalance:${jobId}`,
    ];

    // First try simple GET (works if value was stored via redis.set)
    for (const key of candidates) {
      try {
        const data = await redis.get(key);
        if (data !== null && data !== undefined) {
          return res.json({ jobId, key, data });
        }
      } catch (e) {
        logger.warn(`Redis GET failed for ${key}: ${e.message}`);
      }
    }

    // If not found, try HGETALL via ioredis client (if configured)
    try {
      const iored = redis.getIoredis();
      if (iored) {
        for (const key of candidates) {
          try {
            const obj = await iored.hgetall(key);
            // hgetall returns {} when empty
            if (obj && Object.keys(obj).length > 0) {
              // attempt to parse JSON values where possible
              const parsed = {};
              for (const k of Object.keys(obj)) {
                const v = obj[k];
                try { parsed[k] = JSON.parse(v); } catch (_) { parsed[k] = v; }
              }
              return res.json({ jobId, key, data: parsed });
            }
          } catch (e) {
            logger.warn(`ioredis HGETALL failed for ${key}: ${e.message}`);
          }
        }
      }
    } catch (err) {
      logger.warn('ioredis client unavailable or error while checking hashes', err.message || err);
    }

    return res.status(404).json({ error: 'Job not found' });
  } catch (err) {
    logger.error('getJobStatus error', err);
    return res.status(500).json({ error: 'internal' });
  }
}

module.exports = { getJobStatus };

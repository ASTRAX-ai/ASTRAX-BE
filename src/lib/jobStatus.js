const redis = require('./redis');
const logger = require('./logger');
const { REBALANCE_EVENTS } = require('../config/constants');

/**
 * Job status constants
 */
const JOB_STATUS = {
  CREATED: 'created',
  PROCESSING: 'processing',
  DONE: 'done',
  ERROR: 'error'
};

/**
 * Create initial job record with status
 * @param {string} jobId - Unique job identifier
 * @param {object} jobData - Job payload data
 * @param {string} userPublicKey - User's public key
 * @returns {object} Job record with initial status
 */
function createJobRecord(jobId, jobData, userPublicKey) {
  const now = new Date().toISOString();
  return {
    jobId,
    status: JOB_STATUS.CREATED,
    user: userPublicKey,
    createdAt: now,
    updatedAt: now,
    statusHistory: [
      {
        status: JOB_STATUS.CREATED,
        timestamp: now,
        message: 'Job created and queued'
      }
    ],
    payload: jobData.payload || {},
    type: jobData.type || 'rebalance',
    priority: jobData.priority || 'normal',
    requestMetadata: jobData.requestMetadata || {}
  };
}

/**
 * Update job status with history tracking
 * @param {string} jobId - Job identifier
 * @param {string} newStatus - New status (created/processing/done/error)
 * @param {string} message - Optional status message
 * @returns {Promise<object>} Updated job record
 */
async function updateJobStatus(jobId, newStatus, message = '') {
  try {
    const jobKey = `agent:rebalance:job:${jobId}`;
    
    // Get existing job
    const existing = await redis.get(jobKey);
    if (!existing) {
      logger.warn(`Job ${jobId} not found in Redis for status update`);
      return null;
    }

    const now = new Date().toISOString();
    
    // Update status and history
    const updated = {
      ...existing,
      status: newStatus,
      updatedAt: now,
      statusHistory: [
        ...(existing.statusHistory || []),
        {
          status: newStatus,
          timestamp: now,
          message: message || `Job status updated to ${newStatus}`
        }
      ]
    };

    // Persist back to Redis (TTL 24h)
    await redis.set(jobKey, updated, 24 * 60 * 60);
    
    logger.info(`[job:${newStatus}] jobId=${jobId} status=${newStatus} message="${message}"`);
    
    return updated;
  } catch (err) {
    logger.error(`Failed to update job status for ${jobId}: ${err.message}`);
    throw err;
  }
}

/**
 * Get job record by ID
 * @param {string} jobId - Job identifier
 * @returns {Promise<object|null>} Job record or null if not found
 */
async function getJob(jobId) {
  try {
    const candidates = [
      `agent:rebalance:job:${jobId}`,
      `rebalance:job:${jobId}`,
      `job:rebalance:${jobId}`,
    ];

    for (const key of candidates) {
      try {
        const data = await redis.get(key);
        if (data !== null && data !== undefined) {
          return { ...data, _redisKey: key };
        }
      } catch (e) {
        logger.warn(`Redis GET failed for ${key}: ${e.message}`);
      }
    }

    return null;
  } catch (err) {
    logger.error(`Failed to get job ${jobId}: ${err.message}`);
    throw err;
  }
}

/**
 * Format job response for API
 * @param {object} jobRecord - Job record from Redis
 * @returns {object} Formatted response
 */
function formatJobResponse(jobRecord) {
  if (!jobRecord) return null;

  return {
    jobId: jobRecord.jobId,
    status: jobRecord.status,
    user: jobRecord.user,
    createdAt: jobRecord.createdAt,
    updatedAt: jobRecord.updatedAt,
    type: jobRecord.type || 'rebalance',
    priority: jobRecord.priority || 'normal',
    statusHistory: jobRecord.statusHistory || [],
    payload: jobRecord.payload || {},
    requestMetadata: jobRecord.requestMetadata || {}
  };
}

module.exports = {
  JOB_STATUS,
  createJobRecord,
  updateJobStatus,
  getJob,
  formatJobResponse
};

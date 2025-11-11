const express = require('express');
const controller = require('./rebalance.controller');
const auth = require('../../middleware/auth');

const router = express.Router();

// GET /api/v1/rebalance/:jobId - protected
router.get('/:jobId', auth, controller.getJobStatus);

module.exports = router;

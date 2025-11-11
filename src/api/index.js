const express = require('express');
const router = express.Router();

// mount sub-routers
router.use('/auth', require('./auth'));
router.use('/wallet', require('./wallet'));
router.use('/agent', require('./agent'));
router.use('/rebalance', require('./rebalance'));
router.use('/test', require('./test'));

// health passthrough
router.get('/', (req, res) => res.json({ ok: true }));

module.exports = router;

const app = require('./app');
const { createServer } = require('http');
const { connectMongo } = require('./lib/mongo');
const logger = require('./lib/logger');
const gateway = require('./lib/gateway');

const PORT = process.env.PORT || 3000;

async function start() {
  try {
    await connectMongo();
    
    const httpServer = createServer(app);
    // Initialize WebSocket server
    gateway.initialize(httpServer);
    
    httpServer.listen(PORT, () => {
      logger.info(`HTTP Server listening on port ${PORT}`);
    });
  } catch (err) {
    logger.error('Failed to start server', err);
    process.exit(1);
  }
}

if (require.main === module) start();

module.exports = app;

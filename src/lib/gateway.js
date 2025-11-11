const { Server } = require('socket.io');
const { WEBSOCKET_EVENTS, REBALANCE_EVENTS } = require('../config/constants');
const logger = require('./logger');
const { verifyJwt } = require('./jwt');
const redis = require('./redis');

class WebSocketGateway {
    constructor() {
        this.io = null;
    }

    initialize(httpServer) {
        this.io = new Server(httpServer, {
            cors: {
                origin: process.env.CORS_ORIGIN || '*',
                methods: ['GET', 'POST']
            }
        });

        // Add authentication middleware
        this.io.use(async (socket, next) => {
            try {
                // Get token from auth object or query params
                let token = socket.handshake.auth?.token || socket.handshake.query?.token;
                
                logger.info(`[Socket Auth] Raw token received: ${token ? token.substring(0, 50) + '...' : 'none'}`);
                logger.info(`[Socket Auth] Token starts with Bearer? ${token?.startsWith('Bearer ')}`);
                logger.info(`[Socket Auth] Token length: ${token?.length}`);
                
                if (!token) {
                    logger.warn('[Socket Auth] No token provided');
                    return next(new Error('Authentication token missing'));
                }

                // IMPORTANT: Remove 'Bearer ' prefix if present (common issue)
                let cleanToken = token;
                if (cleanToken.startsWith('Bearer ')) {
                    logger.info('[Socket Auth] Removing Bearer prefix from token');
                    cleanToken = cleanToken.slice(7);
                }
                
                // Handle URL-encoded tokens (from query params)
                if (cleanToken.includes('%')) {
                    logger.info('[Socket Auth] Token appears URL-encoded, decoding...');
                    cleanToken = decodeURIComponent(cleanToken);
                }
                
                logger.info(`[Socket Auth] Clean token length: ${cleanToken.length}`);
                
                // Verify JWT token
                const decoded = this._verifyJwt(cleanToken);
                
                logger.info(`[Socket Auth] Token verified successfully. User: ${decoded.publicKey || decoded.sub}`);
                
                // Attach user data to socket
                socket.user = decoded;
                next();
            } catch (err) {
                logger.error(`[Socket Auth] JWT verification failed: ${err.message}`);
                logger.error(`[Socket Auth] Error type: ${err.name}`);
                if (err.message.includes('malformed')) {
                    logger.error('[Socket Auth] Token is malformed - check for Bearer prefix, URL encoding, or invalid base64');
                } else if (err.message.includes('expired')) {
                    logger.error('[Socket Auth] Token has expired');
                } else if (err.message.includes('invalid signature')) {
                    logger.error('[Socket Auth] Token signature is invalid - check JWT_SECRET');
                }
                next(new Error(`Authentication failed: ${err.message}`));
            }
        });

        this.io.on(WEBSOCKET_EVENTS.CONNECTION, (socket) => {
            const { user } = socket;
            const userId = user && user.publicKey ? user.publicKey : 'unknown';
            logger.info(`Client connected: ${socket.id}, User: ${userId}`);

            socket.on(WEBSOCKET_EVENTS.DISCONNECT, () => {
                logger.info(`Client disconnected: ${socket.id}, User: ${userId}`);
            });

            // Join a room specific to this user
            const room = `user:${userId}`;
            socket.join(room);

            // Deliver any pending events stored in Redis for this user (if any)
            (async () => {
                try {
                    if (userId && userId !== 'unknown') {
                        const pendingKey = `ws:pending:user:${userId}`;
                        const pending = await redis.lrange(pendingKey, 0, -1);
                        if (pending && Array.isArray(pending) && pending.length > 0) {
                            for (const item of pending) {
                                try {
                                    const eventName = item && item.event ? item.event : REBALANCE_EVENTS.CREATED;
                                    const payload = item && item.payload ? item.payload : {};
                                    // emit directly to the connected socket (delivery-on-connect)
                                    socket.emit(eventName, payload);
                                    logger.info(`Delivered pending event ${eventName} to user=${userId} payload=${JSON.stringify(payload)}`);
                                } catch (e) {
                                    logger.error(`Failed to deliver pending item to ${userId}: ${e.message}`);
                                }
                            }
                            // clear pending list after attempting delivery
                            await redis.del(pendingKey);
                            logger.info(`Cleared ${pending.length} pending WS events for user=${userId}`);
                        }
                    }
                } catch (err) {
                    logger.error(`Failed delivering pending WS events to user ${userId}: ${err.message}`);
                }
            })();
        });

        logger.info('WebSocket server initialized');
        
        // Subscribe to Redis pub/sub channel for agent status updates
        this._subscribeToStatusUpdates();
    }

    // Subscribe to Redis channel for real-time status updates from Agent
    async _subscribeToStatusUpdates() {
        try {
            const ioredis = redis.getIoredis?.();
            if (!ioredis) {
                logger.warn('ioredis not available, status update subscription skipped');
                return;
            }

            // Create a separate subscriber connection
            const subscriber = ioredis.duplicate();
            
            subscriber.on('message', async (channel, message) => {
                try {
                    if (channel === 'agent:rebalance:status') {
                        const event = typeof message === 'string' ? JSON.parse(message) : message;
                        const { jobId, status, userId } = event;
                        
                        logger.info(`[Redis Subscribe] Received status update: jobId=${jobId} status=${status} user=${userId}`);
                        
                        // Emit to connected user
                        if (userId) {
                            const room = `user:${userId}`;
                            this.io.to(room).emit(REBALANCE_EVENTS.PROCESSING, { jobId, status });
                            logger.info(`[${REBALANCE_EVENTS.PROCESSING}] jobId=${jobId} user=${userId}`);
                        }
                    }
                } catch (err) {
                    logger.error(`Failed to handle status update from Redis: ${err.message}`);
                }
            });

            subscriber.on('error', (err) => {
                logger.error(`Redis subscriber error: ${err.message}`);
            });

            subscriber.on('subscribe', (channel, count) => {
                logger.info(`[Redis Subscribe] Subscribed to ${channel} (total: ${count})`);
            });

            // Subscribe to the status channel
            await subscriber.subscribe('agent:rebalance:status');
        } catch (err) {
            logger.error(`Failed to setup Redis status subscription: ${err.message}`);
        }
    }

    // emitJobCreated: emit a rebalance-created event to a specific user's room
    // jobId: string, userPublicKey: string, opts: { eventName }
    async emitJobCreated(jobId, userPublicKey, opts = {}) {
        if (!this.io) {
            logger.error('WebSocket server not initialized');
            return;
        }

        const eventName = opts.eventName || REBALANCE_EVENTS.CREATED;

        // Validate event name against known events
        const knownEvents = Object.values(REBALANCE_EVENTS).concat(Object.values(WEBSOCKET_EVENTS));
        if (!knownEvents.includes(eventName)) {
            logger.warn(`Attempting to emit unknown event: ${eventName}`);
        }

        const room = `user:${userPublicKey}`;
        try {
            // fetchSockets gives us the currently connected sockets in the room
            const sockets = await this.io.in(room).fetchSockets();
            const socketCount = Array.isArray(sockets) ? sockets.length : 0;

            // Emit only to the specific user's room
            this.io.to(room).emit(eventName, { jobId });

            // Log with event context and socket count
            logger.info(`[${eventName}] jobId=${jobId} user=${userPublicKey} sockets=${socketCount}`);

            // If no sockets are connected, persist pending event to Redis for later delivery
            if (socketCount === 0) {
                try {
                    const pendingKey = `ws:pending:user:${userPublicKey}`;
                    // push event object and set a TTL (24h)
                    await redis.rpush(pendingKey, { event: eventName, payload: { jobId }, ts: Date.now() });
                    await redis.expire(pendingKey, 24 * 60 * 60);
                    logger.info(`Saved pending event for user=${userPublicKey} key=${pendingKey}`);
                } catch (err) {
                    logger.error(`Failed to save pending WS event for user ${userPublicKey}: ${err.message}`);
                }
            }
        } catch (err) {
            logger.error(`Failed to emit ${eventName} for jobId=${jobId} user=${userPublicKey}: ${err.message}`);
        }
    }

    // Helper method to safely verify JWT with detailed error handling
    _verifyJwt(token) {
        try {
            return verifyJwt(token);
        } catch (err) {
            // Re-throw with additional context
            if (err.message === 'jwt malformed') {
                throw new Error(`JWT malformed: token does not match expected format (${token.substring(0, 30)}...)`);
            }
            throw err;
        }
    }
}

// Create a singleton instance
const gateway = new WebSocketGateway();
module.exports = gateway;
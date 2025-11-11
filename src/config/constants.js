// WebSocket event constants
const WEBSOCKET_EVENTS = {
    JOB_CREATED: 'job:created',
    JOB_UPDATED: 'job:updated',
    JOB_COMPLETED: 'job:completed',
    JOB_FAILED: 'job:failed',
    CONNECTION: 'connection',
    DISCONNECT: 'disconnect'
};

// Rebalance-specific events (namespace: rebalance)
const REBALANCE_EVENTS = {
    CREATED: 'rebalance:created',
    PROCESSING: 'rebalance:processing',
    DONE: 'rebalance:done',
    ERROR: 'rebalance:error'
};
module.exports = {
    WEBSOCKET_EVENTS
    , REBALANCE_EVENTS
};

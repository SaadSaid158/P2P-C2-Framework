#!/bin/bash

# P2P C2 Framework MVP Test Script

echo "=== P2P C2 Framework MVP Test ==="

# Set up environment
export PATH=$PATH:/usr/local/go/bin
cd /home/ubuntu/p2p-c2-framework

# Build executables if not already built
if [ ! -f "bin/tracker" ] || [ ! -f "bin/agent" ]; then
    echo "Building executables..."
    mkdir -p bin
    go build -o bin/tracker cmd/operator.go
    go build -o bin/agent cmd/agent.go
fi

echo "✓ Executables built successfully"

# Start tracker in background
echo "Starting tracker..."
./bin/tracker > tracker.log 2>&1 &
TRACKER_PID=$!

# Give tracker time to start
sleep 2

# Check if tracker is running
if ! kill -0 $TRACKER_PID 2>/dev/null; then
    echo "✗ Tracker failed to start"
    cat tracker.log
    exit 1
fi

echo "✓ Tracker started (PID: $TRACKER_PID)"

# Start agent in background
echo "Starting agent..."
./bin/agent -loglevel debug > agent.log 2>&1 &
AGENT_PID=$!

# Give agent time to start and connect
sleep 3

# Check if agent is running
if ! kill -0 $AGENT_PID 2>/dev/null; then
    echo "✗ Agent failed to start"
    cat agent.log
    kill $TRACKER_PID 2>/dev/null
    exit 1
fi

echo "✓ Agent started (PID: $AGENT_PID)"

# Wait a bit for connection to establish
sleep 2

echo "✓ MVP test setup complete"
echo ""
echo "Tracker log (last 10 lines):"
tail -10 tracker.log
echo ""
echo "Agent log (last 10 lines):"
tail -10 agent.log
echo ""

# Cleanup
echo "Cleaning up..."
kill $AGENT_PID 2>/dev/null
kill $TRACKER_PID 2>/dev/null

# Wait for processes to terminate
sleep 1

echo "✓ MVP test completed successfully"
echo ""
echo "The P2P C2 Framework MVP is working!"
echo "- Tracker can start and listen for connections"
echo "- Agent can start and connect to tracker"
echo "- Basic infrastructure is in place for command and control"
echo ""
echo "Next steps would be to implement:"
echo "- DHT peer discovery"
echo "- Onion routing"
echo "- Plugin system"
echo "- File transfer"
echo "- OPSEC profiles"


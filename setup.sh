#!/bin/bash

# P2P C2 Framework Key Management Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== P2P C2 Framework Key Management ===${NC}"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create key directories
create_key_dirs() {
    print_status "Creating key directories..."
    
    mkdir -p "$PROJECT_DIR/keys/tracker/peers"
    mkdir -p "$PROJECT_DIR/keys/agent/peers"
    
    # Set proper permissions
    chmod 700 "$PROJECT_DIR/keys"
    chmod 700 "$PROJECT_DIR/keys/tracker"
    chmod 700 "$PROJECT_DIR/keys/agent"
    chmod 755 "$PROJECT_DIR/keys/tracker/peers"
    chmod 755 "$PROJECT_DIR/keys/agent/peers"
    
    print_status "Key directories created successfully"
}

# Build the framework
build_framework() {
    print_status "Building P2P C2 Framework..."
    
    cd "$PROJECT_DIR"
    
    # Set Go path
    export PATH=$PATH:/usr/local/go/bin
    
    # Build tracker
    go build -o bin/tracker cmd/operator.go
    if [ $? -ne 0 ]; then
        print_error "Failed to build tracker"
        exit 1
    fi
    
    # Build agent
    go build -o bin/agent cmd/agent.go
    if [ $? -ne 0 ]; then
        print_error "Failed to build agent"
        exit 1
    fi
    
    print_status "Framework built successfully"
}

# Generate initial keys
generate_keys() {
    print_status "Generating initial RSA key pairs..."
    
    # Start tracker briefly to generate its keys
    timeout 5s ./bin/tracker > /dev/null 2>&1 || true
    
    if [ ! -f "$PROJECT_DIR/keys/tracker/local_private.pem" ]; then
        print_error "Failed to generate tracker keys"
        exit 1
    fi
    
    print_status "Tracker keys generated successfully"
    
    # Extract tracker peer ID
    TRACKER_PEER_ID=$(timeout 10s ./bin/tracker 2>&1 | grep "Tracker ID:" | awk '{print $3}' | head -1 || echo "")
    
    if [ -z "$TRACKER_PEER_ID" ]; then
        print_warning "Could not extract tracker peer ID automatically"
        print_warning "You will need to run the tracker first and note its peer ID"
    else
        print_status "Tracker Peer ID: $TRACKER_PEER_ID"
        echo "$TRACKER_PEER_ID" > "$PROJECT_DIR/tracker_peer_id.txt"
    fi
}

# Setup key exchange
setup_key_exchange() {
    print_status "Setting up key exchange between tracker and agent..."
    
    # For now, we'll copy the public keys manually
    # In a real deployment, this would be done through a secure channel
    
    if [ -f "$PROJECT_DIR/keys/tracker/local_public.pem" ]; then
        # This is a simplified setup - in production, proper key distribution is needed
        print_warning "Manual key exchange required for production use"
        print_warning "Tracker public key: $PROJECT_DIR/keys/tracker/local_public.pem"
    fi
}

# Display usage instructions
show_usage() {
    echo -e "\n${BLUE}=== Usage Instructions ===${NC}"
    echo -e "${GREEN}1. Start the tracker:${NC}"
    echo -e "   ./bin/tracker"
    echo -e ""
    echo -e "${GREEN}2. Note the tracker peer ID from the output${NC}"
    echo -e ""
    echo -e "${GREEN}3. Start an agent:${NC}"
    echo -e "   ./bin/agent -tracker-id <TRACKER_PEER_ID>"
    echo -e ""
    echo -e "${GREEN}4. Use the tracker CLI to manage agents${NC}"
    echo -e ""
    echo -e "${YELLOW}Security Notes:${NC}"
    echo -e "- Keys are stored in ./keys/ directory"
    echo -e "- Ensure proper key distribution in production"
    echo -e "- Use TLS for network communications"
    echo -e "- Regularly rotate keys and monitor for anomalies"
    echo -e ""
}

# Main execution
main() {
    case "${1:-setup}" in
        "setup")
            create_key_dirs
            build_framework
            generate_keys
            setup_key_exchange
            show_usage
            ;;
        "build")
            build_framework
            ;;
        "keys")
            create_key_dirs
            generate_keys
            ;;
        "clean")
            print_status "Cleaning build artifacts and keys..."
            rm -rf "$PROJECT_DIR/bin"
            rm -rf "$PROJECT_DIR/keys"
            rm -f "$PROJECT_DIR/tracker_peer_id.txt"
            print_status "Cleanup completed"
            ;;
        "help"|"-h"|"--help")
            echo "Usage: $0 [setup|build|keys|clean|help]"
            echo ""
            echo "Commands:"
            echo "  setup  - Full setup (default): create dirs, build, generate keys"
            echo "  build  - Build executables only"
            echo "  keys   - Generate keys only"
            echo "  clean  - Remove all generated files"
            echo "  help   - Show this help message"
            ;;
        *)
            print_error "Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"


#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

BINARY="./bin/peer"
OUTPUT_FILE="test_results.txt"
LISTEN_PORT=":4433"
CONNECT_PORT=":4434"
CONNECT_ADDR="localhost:4433"

METHODS=("none" "kyber" "frodo" "mlkem")

echo -e "${GREEN}Building the chat application...${NC}"
make
if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo -e "${RED}Binary not found at $BINARY! Check Makefile output path.${NC}"
    exit 1
fi

echo "Test Results" > $OUTPUT_FILE
echo "=============" >> $OUTPUT_FILE

run_test() {
    local method=$1
    local pqc_flag=""
    if [ "$method" != "none" ]; then
        pqc_flag="-pqc $method"
    fi

    echo -e "${GREEN}Testing $method...${NC}"

    if lsof -i $LISTEN_PORT >/dev/null 2>&1 || lsof -i $CONNECT_PORT >/dev/null 2>&1; then
        echo -e "${RED}Port $LISTEN_PORT or $CONNECT_PORT in use, killing processes...${NC}"
        killall -9 peer 2>/dev/null
        sleep 1
    fi

    $BINARY -listen $LISTEN_PORT $pqc_flag > listener_$method.log 2>&1 &
    LISTENER_PID=$!
    echo "Listener PID: $LISTENER_PID"
    sleep 1

    $BINARY -listen $CONNECT_PORT -connect $CONNECT_ADDR $pqc_flag -test > connector_$method.log 2>&1 &
    CONNECTOR_PID=$!
    echo "Connector PID: $CONNECTOR_PID"

    for i in {1..10}; do
        if ! ps -p $CONNECTOR_PID > /dev/null; then
            break
        fi
        sleep 1
    done
    if ps -p $CONNECTOR_PID > /dev/null; then
        echo -e "${RED}Connector timed out for $method, killing...${NC}"
        kill -9 $CONNECTOR_PID 2>/dev/null
    fi

    kill -9 $LISTENER_PID 2>/dev/null
    wait $LISTENER_PID 2>/dev/null

    echo "Method: $method" >> $OUTPUT_FILE
    echo "----------------" >> $OUTPUT_FILE
    
    # Extract key exchange line without ANSI codes
    KEY_EXCHANGE=$(grep "Key Exchange" listener_$method.log | tail -n 1 | sed 's/\x1B\[[0-9;]*m//g')
    if [ -n "$KEY_EXCHANGE" ]; then
        echo "$KEY_EXCHANGE" >> $OUTPUT_FILE
    else
        echo "Key Exchange Time: Not found" >> $OUTPUT_FILE
    fi
    
    # Extract size lines without ANSI codes
    grep "Small\|Medium\|Large" connector_$method.log | sed 's/\x1B\[[0-9;]*m//g' >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE

    echo "Logs saved as listener_$method.log and connector_$method.log"
}

for method in "${METHODS[@]}"; do
    run_test "$method"
    sleep 1
done

echo -e "${GREEN}Tests completed! Results saved to $OUTPUT_FILE${NC}"
cat $OUTPUT_FILE
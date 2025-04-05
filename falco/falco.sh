LOG_FILE="falco_scan.log"

# Check if Falco is installed
if ! command -v falco &> /dev/null; then
    echo "Falco is not installed. Please install it first."
    exit 1
fi

# Ensure the script has proper permissions to write to the log file
if ! touch "$LOG_FILE" &> /dev/null; then
    echo "Error: Cannot write to $LOG_FILE. Check file permissions."
    exit 1
fi

# Start Falco in the background and redirect output to log file
echo "Starting Falco and logging alerts to $LOG_FILE..."
sudo stdbuf -oL falco -o output_format=json > "$LOG_FILE" 2>&1 </dev/null &
falco_pid=$!

# Function to clean up and stop Falco when the script exits
cleanup() {
    echo "Stopping Falco..."
    kill "$falco_pid" &> /dev/null
    exit 0
}

# Trap signals (SIGINT, SIGTERM) to trigger the cleanup function
trap cleanup SIGINT SIGTERM

# Ensure only one tail process is running
if ! pgrep -f "tail -f $LOG_FILE" > /dev/null; then
    echo "Starting log monitoring..."
    tail -f "$LOG_FILE" &
fi

# Wait for Falco to exit
wait "$falco_pid"

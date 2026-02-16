#!/usr/bin/env bash

SERVER="127.0.0.1"
PORT=5224

# Start nc in coprocess
coproc NETCAT { nc "$SERVER" "$PORT"; }

# NETCAT[0] = read from server
# NETCAT[1] = write to server

echo "Connected to $SERVER:$PORT"
echo "Type messages, Ctrl+C to quit"

# Background receiver
{
    while true; do
        # Read 4-byte length header
        LEN_BYTES=$(dd bs=1 count=4 <&"${NETCAT[0]}" 2>/dev/null | xxd -p)
        [ -z "$LEN_BYTES" ] && { echo "Server closed connection"; exit 0; }

        # Convert big-endian hex to decimal
        LEN=$((16#${LEN_BYTES:0:2} << 24 | 16#${LEN_BYTES:2:2} << 16 | 16#${LEN_BYTES:4:2} << 8 | 16#${LEN_BYTES:6:2}))

        # Read the payload
        PAYLOAD=$(dd bs=1 count="$LEN" <&"${NETCAT[0]}" 2>/dev/null)
        echo -e "\n[recv] $PAYLOAD"
        echo -n "> "
    done
} &

# Sender loop
while true; do
    echo -n "> "
    read -r INPUT || break

    [ -z "$INPUT" ] && continue

    LEN=$(printf "%s" "$INPUT" | wc -c)
    LEN_BYTES=$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
        $((LEN >> 24 & 0xff)) \
        $((LEN >> 16 & 0xff)) \
        $((LEN >> 8 & 0xff)) \
        $((LEN & 0xff)))

    # Send length + payload
    {
        printf "$LEN_BYTES"
        printf "%s" "$INPUT"
    } >&"${NETCAT[1]}"
done

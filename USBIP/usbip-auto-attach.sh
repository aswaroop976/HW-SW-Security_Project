#!/bin/bash

SERVER="10.0.0.1"
INTERVAL=5   # seconds between checks

while true; do
    # Get exportable devices on the server.
    mapfile -t remote_busids < <(
        usbip list -r "$SERVER" 2>/dev/null | \
        awk '/^[[:space:]]+[0-9.-]+:/ { sub(/:/,"",$1); print $1 }'
    )

    # Get currently attached remote busids on this client
    mapfile -t attached_busids < <(
        usbip port 2>/dev/null | \
        awk '/usbip:\/\// { sub(/.*\//,""); print }'
    )

    # Attach any remote busid that isn't already attached
    for b in "${remote_busids[@]}"; do
        [ -z "$b" ] && continue
        if printf '%s\n' "${attached_busids[@]}" | grep -qx "$b"; then
            # already attached
            continue
        fi

        echo "[usbip-auto] Attaching $b from $SERVER"
        usbip attach -r "$SERVER" -b "$b" || \
            echo "[usbip-auto] Failed to attach $b"
    done

    sleep "$INTERVAL"
done


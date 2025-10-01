#!/bin/bash

# Function to convert a hex-encoded LDAP objectSid to a Windows SID format
ldap_objectSid_to_sid() {
    local hex="$1"
    
    # Remove "0x" prefix if present
    hex="${hex#0x}"

    # Convert to an array of bytes
    sid=()
    for ((i=0; i<${#hex}; i+=2)); do
        sid+=("0x${hex:i:2}")
    done

    # Extract components
    revision=$((sid[0]))         # Revision
    subAuthCount=$((sid[1]))     # Number of sub-authorities

    # Extract identifier authority (big-endian, 6 bytes)
    idAuthority=$(( (sid[2] << 40) | (sid[3] << 32) | (sid[4] << 24) | (sid[5] << 16) | (sid[6] << 8) | sid[7] ))

    # Read sub-authorities (little-endian 4-byte values)
    subAuthorities=()
    for ((i=0; i<subAuthCount; i++)); do
        startIndex=$((8 + i * 4))
        subAuthorities+=($((sid[startIndex] | (sid[startIndex+1] << 8) | (sid[startIndex+2] << 16) | (sid[startIndex+3] << 24))))
    done

    # Construct SID string
    sidString="S-$revision-$idAuthority"
    for sub in "${subAuthorities[@]}"; do
        sidString+="-${sub}"
    done

    echo "$sidString"
}

ldap_objectSid_to_sid $1

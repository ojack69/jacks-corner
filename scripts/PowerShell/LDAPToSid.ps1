function Convert-LdapObjectSidToSid {
    param (
        [string]$hexString
    )

    # Remove "0x" if present
    $hexString = $hexString -replace '^0x', ''

    # Convert hex to byte array
    $bytes = [byte[]]::new($hexString.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [convert]::ToByte($hexString.Substring($i * 2, 2), 16)
    }

    # Extract revision and sub-authority count
    $revision = $bytes[0]
    $subAuthCount = $bytes[1]

    # Extract identifier authority (big-endian)
    $idAuthority = ($bytes[2..7] -join '') -replace '^0+', ''
    if (-not $idAuthority) { $idAuthority = "0" }

    # Extract sub-authorities (little-endian)
    $subAuthorities = @()
    for ($i = 0; $i -lt $subAuthCount; $i++) {
        $startIndex = 8 + ($i * 4)
        $subAuthority = [BitConverter]::ToUInt32($bytes[$startIndex..($startIndex + 3)], 0)
        $subAuthorities += $subAuthority
    }

    # Construct SID
    $sid = "S-$revision-$idAuthority" + ($subAuthorities -join '-')
    return $sid
}


# Allow parameters to be passed in
param(
    [Parameter(Mandatory = $false)]
    [string]$FilePath = $null,

    [Parameter(Mandatory = $false)]
    [string]$Content = $null,

    [Parameter(Mandatory = $false)]
    [guid]$Context = [guid]::ParseExact('6ba7b810-9dad-11d1-80b4-00c04fd430c8', 'D')
)
# RFC 4122 UUID version 5 generator using SHA-1 hash of file content or string content
# Default context is ns:DNS as defined in RFC 4122 Appendix C
# https://www.rfc-editor.org/rfc/rfc4122#appendix-C

# RFC 4122 states the following algorithm for generating a UUID version 5:
#
# The algorithm for generating a UUID from a name and a name space are
#    as follows:
#
#    o  Allocate a UUID to use as a "name space ID" for all UUIDs
#       generated from names in that name space; see Appendix C for some
#       pre-defined values.
#
#    o  Choose either MD5 [4] or SHA-1 [8] as the hash algorithm; If
#       backward compatibility is not an issue, SHA-1 is preferred.
#
#
#
#
# Leach, et al.               Standards Track                    [Page 13]
#
# RFC 4122                  A UUID URN Namespace                 July 2005
#
#
#    o  Convert the name to a canonical sequence of octets (as defined by
#       the standards or conventions of its name space); put the name
#       space ID in network byte order.
#
#    o  Compute the hash of the name space ID concatenated with the name.
#
#    o  Set octets zero through 3 of the time_low field to octets zero
#       through 3 of the hash.
#
#    o  Set octets zero and one of the time_mid field to octets 4 and 5 of
#       the hash.
#
#    o  Set octets zero and one of the time_hi_and_version field to octets
#       6 and 7 of the hash.
#
#    o  Set the four most significant bits (bits 12 through 15) of the
#       time_hi_and_version field to the appropriate 4-bit version number
#       from Section 4.1.3.
#
#    o  Set the clock_seq_hi_and_reserved field to octet 8 of the hash.
#
#    o  Set the two most significant bits (bits 6 and 7) of the
#       clock_seq_hi_and_reserved to zero and one, respectively.
#
#    o  Set the clock_seq_low field to octet 9 of the hash.
#
#    o  Set octets zero through five of the node field to octets 10
#       through 15 of the hash.
#
#    o  Convert the resulting UUID to local byte order.


# If FilePath is provided, read the file content
if ($FilePath) {
    if (-not (Test-Path $FilePath)) {
        throw "The specified file does not exist: $FilePath"
    }
    $Content = Get-Content -Path $FilePath -Raw
}

$content_bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)

# Debug out the content bytes
Write-Host "Length of content bytes: $($content_bytes.Length)"
Write-Host "Content bytes: $([BitConverter]::ToString($content_bytes))"

Write-Host "Using context GUID: $Context"

# A GUID is a 16-byte structure:
# - Data0 uint32
# - Data1 uint16
# - Data2 uint16
# - Data3 byte[8]
# Convert the context GUID to a byte array in network byte order
$context_bytes = $Context.ToByteArray()
# Reverse the byte order for the first three parts to match network byte order
[Array]::Reverse($context_bytes, 0, 4)  # Data0
[Array]::Reverse($context_bytes, 4, 2)  # Data1
[Array]::Reverse($context_bytes, 6, 2)  # Data2

# Debug out the context bytes
Write-Host "Length of context bytes: $($context_bytes.Length)"
Write-Host "Context GUID bytes: $([BitConverter]::ToString($context_bytes))"

# Create a temporary file to store the content
$tempFile = [System.IO.Path]::GetTempFileName()

# Write context bytes to the temporary file
[System.IO.File]::WriteAllBytes($tempFile, $context_bytes + $content_bytes)

$hash = Get-FileHash -Path $tempFile -Algorithm 'SHA1' | Select-Object Hash
Write-Host "Hash of content: $($hash.Hash)"

# Extract the first 32 characters of the hash and parse it into a Guid
$guid = [guid]::ParseExact($hash.Hash.Substring(0, 32), 'N')

# Set the correct bits to indicate UUID version 5 and SHA-1
# Octets 0-3 of time_low are set to octets 0-3 of the hash
# Octets 4-5 of time_mid are set to octets 4-5 of the hash
# Octets 6-7 of time_hi_and_version are set to octets 6-7 of the hash
# 4 most significant bits of time_hi_and_version are set to version 5
# Octet 8 of clock_seq_hi_and_reserved is set to octet 8 of the hash
# 2 most significant bits of clock_seq_hi_and_reserved are set to 1 and 0 respectively
# Octet 9 of clock_seq_low is set to octet 9 of the hash
# Octets 10-15 of node are set to octets 10-15 of the hash
# The resulting UUID is then constructed from these bytes
# Convert the resulting UUID to local byte order
$guid_bytes = $guid.ToByteArray()
[Array]::Reverse($guid_bytes, 6, 2)  # Data2
$guid_bytes[6] = ($guid_bytes[6] -band 0x0f) -bor 0x50 # Set version to 5
$guid_bytes[8] = ($guid_bytes[8] -band 0x3f) -bor 0x80 # Set variant to RFC 4122
# [Array]::Reverse($guid_bytes, 0, 4)  # Data0
[Array]::Reverse($guid_bytes, 6, 2)  # Data2

$guid = [guid]::new($guid_bytes)

# Clean up the temporary file
Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue

$guid
# End of script
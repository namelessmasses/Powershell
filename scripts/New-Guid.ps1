# Allow parameters to be passed in
# RFC 4122 UUID version 5 generator using SHA-1 hash of file content or string content
# Default context is ns:DNS as defined in RFC 4122 Appendix C
# https://www.rfc-editor.org/rfc/rfc4122#appendix-C$

# If FilePath is provided, read the file content
if ($FilePath) {
    if (-not (Test-Path $FilePath)) {
        throw "The specified file does not exist: $FilePath"
    }
    $Content = Get-Content -Path $FilePath -Raw
}

$content_bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)

# If $Context is all bits set to 1

if ($Context) {
    # Write context guid bytes to the temporary file
    $context_bytes = $Context.ToByteArray()
    [System.IO.File]::WriteAllBytes($tempFile, $context_bytes)    
}

# Write content bytes to the temporary file
[System.IO.File]::WriteAllBytes($tempFile, $content_bytes)

$hash = Get-FileHash -Path $tempFile -Algorithm 'SHA1' | Select-Object Hash

# Extract the first 32 characters of the hash and parse it into a Guid
$guid = [guid]::ParseExact($hash.Hash.Substring(0, 32), 'N')

# Set the correct bits to indicate UUID version 5 and SHA-1
$guid_bytes = $guid.ToByteArray()
$guid_bytes[6] = ($guid_bytes[6] -band 0x0f) -bor 0x50 # Set version to 5
$guid_bytes[8] = ($guid_bytes[8] -band 0x3f) -bor 0x80 # Set variant to RFC 4122

$guid = [guid]::new($guid_bytes)

# Clean up the temporary file
Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue

$guid
# End of script
param(
    [Parameter(Mandatory)][string[]]$Files,
    [Parameter(Mandatory)][int[]]$Machines
)
$ErrorActionPreference = 'Stop'
if (!$IsWindows) { throw 'Windows is required for Authenticode verification.' }
if ($Files.Count -ne $Machines.Count -or !$Files.Count) { throw 'Each executable needs its expected PE machine.' }
$workspace = [IO.Path]::GetFullPath((Get-Location).Path).TrimEnd('\') + '\'
$seen = @{}
$paths = for ($i = 0; $i -lt $Files.Count; $i++) {
    $file = Get-Item -LiteralPath $Files[$i]
    if ($file.PSIsContainer -or $file.Extension -ne '.exe' -or
        ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        !$file.FullName.StartsWith($workspace, [StringComparison]::OrdinalIgnoreCase) -or $seen.ContainsKey($file.FullName)) {
        throw 'Only distinct, owned executables inside the checkout may be signed.'
    }
    $seen[$file.FullName] = $true
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    if ($bytes.Length -lt 64 -or [BitConverter]::ToUInt16($bytes, 0) -ne 0x5a4d) { throw 'Invalid MZ executable.' }
    $offset = [BitConverter]::ToInt32($bytes, 60)
    if ($offset -lt 64 -or $offset -gt ($bytes.Length - 6) -or [BitConverter]::ToUInt32($bytes, $offset) -ne 0x4550 -or
        [BitConverter]::ToUInt16($bytes, $offset + 4) -ne $Machines[$i]) { throw 'Unexpected PE architecture.' }
    $file.FullName
}
foreach ($name in 'SIGNING_ENDPOINT', 'SIGNING_ACCOUNT_NAME', 'SIGNING_CERTIFICATE_PROFILE') {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) { throw "Missing signing configuration: $name" }
}
Install-Module TrustedSigning -RequiredVersion 0.5.8 -Force -Repository PSGallery -Scope CurrentUser
Import-Module TrustedSigning -RequiredVersion 0.5.8
foreach ($file in $paths) {
    Invoke-TrustedSigning -Endpoint $env:SIGNING_ENDPOINT -CodeSigningAccountName $env:SIGNING_ACCOUNT_NAME `
        -CertificateProfileName $env:SIGNING_CERTIFICATE_PROFILE -FileDigest SHA256 -TimestampDigest SHA256 `
        -TimestampRfc3161 http://timestamp.acs.microsoft.com -Files $file
    $signature = Get-AuthenticodeSignature -LiteralPath $file
    if ($signature.Status -ne 'Valid' -or !$signature.TimeStamperCertificate -or
        $signature.SignerCertificate.GetNameInfo('SimpleName', $false) -ne 'TECNO BROS STUDIOS, S.L.') {
        throw 'The executable must have a valid, timestamped TECNO BROS signature.'
    }
    Write-Host "Verified signature: $([IO.Path]::GetFileName($file))"
}

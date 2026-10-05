$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..' 'lib' 'governor-retirement-approval.ps1')

# Ephemeral RSA-2048 self-signed issuer certificate (issue #2968
# CCV1/W2): valid now-5min..+1h, never written to any certificate
# store. The PFX carries a throwaway (empty) password because
# issuance loads it WITHOUT a password: a password-protected PFX
# throws out of the constructor, fail-closed.
$key = [System.Security.Cryptography.RSA]::Create(2048)
$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    'CN=eliot-retirement-approval-issuer-certificate-test',
    $key,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$issuerCertificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(1))
$thumbprint = [string]$issuerCertificate.Thumbprint
$pfxPath = Join-Path ([System.IO.Path]::GetTempPath()) "cb-2968-$([System.IO.Path]::GetRandomFileName()).pfx"
$cerPath = Join-Path ([System.IO.Path]::GetTempPath()) "cb-2968-$([System.IO.Path]::GetRandomFileName()).cer"
try {
    [System.IO.File]::WriteAllBytes($pfxPath, $issuerCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, ''))
    [System.IO.File]::WriteAllBytes($cerPath, $issuerCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    $entry = [pscustomobject]@{ role = 'retirement-approval'; receipt_certificate_thumbprint = $thumbprint }

    # Case 1: resolve by PFX path with a matching policy entry.
    $resolved = Resolve-GovernorRetirementIssuerCertificate $entry $pfxPath
    if ([string]$resolved.Thumbprint -cne $thumbprint) {
        throw "the resolved issuer certificate thumbprint $($resolved.Thumbprint) is not the pinned thumbprint $thumbprint"
    }
    if (-not $resolved.HasPrivateKey) {
        throw 'the resolved issuer certificate carries no private key'
    }

    # Case 2: the same PFX with a DIFFERENT 40-hex pinned thumbprint.
    $mismatchedEntry = [pscustomobject]@{ role = 'retirement-approval'; receipt_certificate_thumbprint = ('BB' * 20) }
    try {
        Resolve-GovernorRetirementIssuerCertificate $mismatchedEntry $pfxPath
        throw 'must refuse'
    } catch {
        if ($_.Exception.Message -notmatch 'does not match the admitted') { throw }
    }

    # Case 3: an unknown 40-hex thumbprint input.
    try {
        Resolve-GovernorRetirementIssuerCertificate $entry ('AA' * 20)
        throw 'must refuse'
    } catch {
        if ($_.Exception.Message -notmatch 'no certificate with thumbprint') { throw }
    }

    # Case 4: a blank certificate path.
    try {
        Resolve-GovernorRetirementIssuerCertificate $entry ''
        throw 'must refuse'
    } catch {
        if ($_.Exception.Message -notmatch 'explicit thumbprint or absolute') { throw }
    }

    # Case 5: the public-only .cer export of the same certificate.
    try {
        Resolve-GovernorRetirementIssuerCertificate $entry $cerPath
        throw 'must refuse'
    } catch {
        if ($_.Exception.Message -notmatch 'no accessible private key') { throw }
    }
}
finally {
    Remove-Item -LiteralPath $pfxPath -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $cerPath -ErrorAction SilentlyContinue
    $issuerCertificate.Dispose()
    $key.Dispose()
}
Write-Output 'ISSUER-CERT-OK'

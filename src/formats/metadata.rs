use serde::Deserialize;
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct FileMetadata {
    pub file_description: String,
    pub company_name: String,
    pub file_version: String,
    pub product_name: String,
    pub product_version: String,
    pub original_filename: String,
    pub internal_name: String,
    pub comments: String,
    pub legal_copyright: String,
    pub signature_status: String,
    pub signer_subject: String,
    pub signer_issuer: String,
    pub signer_thumbprint: String,
}

#[derive(Debug, Deserialize, Default)]
struct FileMetadataJson {
    #[serde(rename = "FileDescription", default)]
    file_description: String,
    #[serde(rename = "CompanyName", default)]
    company_name: String,
    #[serde(rename = "FileVersion", default)]
    file_version: String,
    #[serde(rename = "ProductName", default)]
    product_name: String,
    #[serde(rename = "ProductVersion", default)]
    product_version: String,
    #[serde(rename = "OriginalFilename", default)]
    original_filename: String,
    #[serde(rename = "InternalName", default)]
    internal_name: String,
    #[serde(rename = "Comments", default)]
    comments: String,
    #[serde(rename = "LegalCopyright", default)]
    legal_copyright: String,
    #[serde(rename = "SignatureStatus", default)]
    signature_status: String,
    #[serde(rename = "SignerSubject", default)]
    signer_subject: String,
    #[serde(rename = "SignerIssuer", default)]
    signer_issuer: String,
    #[serde(rename = "SignerThumbprint", default)]
    signer_thumbprint: String,
}

pub fn query_file_metadata(path: &str) -> Result<FileMetadata, String> {
    #[cfg(windows)]
    {
        let script = r#"
$ErrorActionPreference = 'Stop'
$path = $env:RESX_PATH
$item = Get-Item -LiteralPath $path
$vi = $item.VersionInfo
$sig = Get-AuthenticodeSignature -LiteralPath $path
[ordered]@{
  FileDescription = [string]$vi.FileDescription
  CompanyName = [string]$vi.CompanyName
  FileVersion = [string]$vi.FileVersion
  ProductName = [string]$vi.ProductName
  ProductVersion = [string]$vi.ProductVersion
  OriginalFilename = [string]$vi.OriginalFilename
  InternalName = [string]$vi.InternalName
  Comments = [string]$vi.Comments
  LegalCopyright = [string]$vi.LegalCopyright
  SignatureStatus = [string]$sig.Status
  SignerSubject = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { '' }
  SignerIssuer = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Issuer } else { '' }
  SignerThumbprint = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Thumbprint } else { '' }
} | ConvertTo-Json -Compress
"#;

        let output = Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-Command")
            .arg(script)
            .env("RESX_PATH", path)
            .output()
            .map_err(|e| format!("query file metadata: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(if stderr.is_empty() {
                "metadata query failed".to_owned()
            } else {
                format!("metadata query failed: {}", stderr)
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: FileMetadataJson = serde_json::from_str(stdout.trim())
            .map_err(|e| format!("parse metadata json: {}", e))?;
        Ok(FileMetadata {
            file_description: parsed.file_description,
            company_name: parsed.company_name,
            file_version: parsed.file_version,
            product_name: parsed.product_name,
            product_version: parsed.product_version,
            original_filename: parsed.original_filename,
            internal_name: parsed.internal_name,
            comments: parsed.comments,
            legal_copyright: parsed.legal_copyright,
            signature_status: parsed.signature_status,
            signer_subject: parsed.signer_subject,
            signer_issuer: parsed.signer_issuer,
            signer_thumbprint: parsed.signer_thumbprint,
        })
    }

    #[cfg(not(windows))]
    {
        let _ = path;
        Err("file metadata query is only supported on Windows".to_owned())
    }
}

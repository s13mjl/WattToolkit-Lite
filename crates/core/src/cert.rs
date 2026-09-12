//! Certificate management, mirroring the original CertificateManager.
//!
//! Generates a self-signed root CA and per-SNI leaf certificates for the
//! MITM reverse proxy (Hosts mode). Uses rcgen with an ECDSA P-256 key
//! (ring provider). The root cert is stored in the app data directory;
//! install/remove use certutil / PowerShell against the LocalMachine Root
//! store (requires elevation, like the original).

use crate::paths;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;

/// Root certificate name (mirrors original "SteamTools Certificate").
pub const ROOT_CERT_NAME: &str = "WattToolkit-Lite Certificate";

/// Root certificate validity in days (mirrors original CertificateConstants).
pub const CERT_VALID_DAYS: i64 = 300;

fn cer_path() -> std::path::PathBuf {
    paths::cert_dir().join("root.cer")
}

fn key_path() -> std::path::PathBuf {
    paths::cert_dir().join("root.key.der")
}

pub struct RootCertificate {
    pub der: Vec<u8>,
    pub key_pkcs8: Vec<u8>,
    pub not_after: SystemTime,
}

impl RootCertificate {
    fn valid(&self) -> bool {
        SystemTime::now() < self.not_after
    }
}

/// The certificate manager, mirroring CertificateManagerImpl.
#[derive(Clone)]
pub struct CertificateManager {
    inner: Arc<Mutex<Option<Arc<RootCertificate>>>>,
}

impl CertificateManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
        }
    }

    /// Load (or lazily keep absent) the root certificate.
    pub fn load(&self) -> Option<Arc<RootCertificate>> {
        {
            let g = self.inner.lock().ok()?;
            if let Some(rc) = g.as_ref() {
                if rc.valid() {
                    return Some(rc.clone());
                }
            }
        }
        if cer_path().exists() && key_path().exists() {
            let cer = std::fs::read(cer_path()).ok()?;
            let key = std::fs::read(key_path()).ok()?;
            if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(&cer) {
                let dt = parsed.tbs_certificate.validity.not_after.to_datetime();
                let not_after = SystemTime::UNIX_EPOCH
                    + Duration::from_secs(dt.unix_timestamp().max(0) as u64);
                let rc = RootCertificate {
                    der: cer,
                    key_pkcs8: key,
                    not_after,
                };
                if rc.valid() {
                    let out = Arc::new(rc);
                    if let Ok(mut g) = self.inner.lock() {
                        *g = Some(out.clone());
                    }
                    return Some(out);
                }
            }
        }
        None
    }

    /// Generate the root certificate (mirrors GenerateCertificate).
    pub fn generate(&self) -> Result<Arc<RootCertificate>, String> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
        let mut params =
            CertificateParams::new(vec![ROOT_CERT_NAME.to_string()]).map_err(|e| e.to_string())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, ROOT_CERT_NAME);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(CERT_VALID_DAYS);
        let cert = params.self_signed(&key).map_err(|e| e.to_string())?;

        let not_after_sys = SystemTime::now() + Duration::from_secs((CERT_VALID_DAYS as u64) * 86400);
        let rc = RootCertificate {
            der: cert.der().to_vec(),
            key_pkcs8: key.serialize_der(),
            not_after: not_after_sys,
        };
        std::fs::write(cer_path(), &rc.der).map_err(|e| e.to_string())?;
        std::fs::write(key_path(), &rc.key_pkcs8).map_err(|e| e.to_string())?;
        let out = Arc::new(rc);
        if let Ok(mut g) = self.inner.lock() {
            *g = Some(out.clone());
        }
        Ok(out)
    }

    /// Get-or-create the root certificate.
    pub fn root(&self) -> Result<Arc<RootCertificate>, String> {
        if let Some(rc) = self.load() {
            return Ok(rc);
        }
        self.generate()
    }

    /// Generate a leaf (server) certificate for the given SNI, signed by the root.
    /// Returns (cert_der, leaf_key_pkcs8_der).
    pub fn leaf_for(
        &self,
        sni: &str,
        rc: &Arc<RootCertificate>,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let root_key = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(rc.key_pkcs8.clone()),
            &PKCS_ECDSA_P256_SHA256,
        )
        .map_err(|e| e.to_string())?;
        let issuer = Issuer::from_ca_cert_der(
            &CertificateDer::from(rc.der.clone()),
            root_key,
        )
        .map_err(|e| e.to_string())?;

        let leaf_key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
        let mut params =
            CertificateParams::new(vec![sni.to_string()]).map_err(|e| e.to_string())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, sni);
        params.distinguished_name = dn;
        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(30);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        let cert = params.signed_by(&leaf_key, &issuer).map_err(|e| e.to_string())?;
        Ok((cert.der().to_vec(), leaf_key.serialize_der()))
    }

    /// Install the root certificate into the LocalMachine Root store (needs admin).
    pub fn install(&self) -> Result<String, String> {
        self.root()?;
        let cer = cer_path();
        let out = std::process::Command::new("certutil")
            .args(["-addstore", "Root"])
            .arg(cer.as_os_str())
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok("installed".to_string())
        } else {
            Err(format!(
                "certutil failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ))
        }
    }

    /// Remove our root certificate from the LocalMachine Root store (needs admin).
    pub fn remove(&self) -> Result<String, String> {
        let ps = format!(
            r"Get-ChildItem Cert:LocalMachineRoot | Where-Object {{ $_.Subject -like 'CN=*{name}*' }} | ForEach-Object {{ Remove-Item $_.PSPath -Force }}",
            name = ROOT_CERT_NAME
        );
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps])
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok("removed".to_string())
        } else {
            Err(format!(
                "remove failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ))
        }
    }

    /// Whether the root certificate is installed in the store.
    pub fn is_installed(&self) -> bool {
        let ps = r"Get-ChildItem Cert:LocalMachineRoot | Where-Object { $_.Subject -like 'CN=*WattToolkit-Lite Certificate*' } | Select-Object -First 1 -ExpandProperty Subject";
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", ps])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                !String::from_utf8_lossy(&o.stdout).trim().is_empty()
            }
            _ => false,
        }
    }

    /// Human-readable certificate info (mirrors GetCertificateInfo).
    pub fn info(&self) -> String {
        match self.load() {
            Some(rc) => {
                if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(&rc.der) {
                    format!(
                        "Subject: {}
Issuer: {}
Valid from: {}
Valid to: {}
Serial: {}",
                        parsed.tbs_certificate.subject(),
                        parsed.tbs_certificate.issuer(),
                        parsed.tbs_certificate.validity.not_before,
                        parsed.tbs_certificate.validity.not_after,
                        parsed.tbs_certificate.serial
                    )
                } else {
                    "无法解析证书".to_string()
                }
            }
            None => "证书尚未生成".to_string(),
        }
    }
}

impl Default for CertificateManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache of generated leaf certificates (per SNI).
#[derive(Default)]
pub struct LeafCache {
    map: Mutex<HashMap<String, (Vec<u8>, Vec<u8>)>>,
}

impl LeafCache {
    pub fn get_or_create(
        &self,
        sni: &str,
        cm: &CertificateManager,
        root: &Arc<RootCertificate>,
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        {
            if let Ok(g) = self.map.lock() {
                if let Some(v) = g.get(sni) {
                    return Some((v.0.clone(), v.1.clone()));
                }
            }
        }
        let v = cm.leaf_for(sni, root).ok()?;
        if let Ok(mut g) = self.map.lock() {
            g.insert(sni.to_string(), (v.0.clone(), v.1.clone()));
        }
        Some(v)
    }
}

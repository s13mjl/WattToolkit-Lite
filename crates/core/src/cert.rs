//! Certificate management, mirroring the original CertificateManager.
//!
//! Generates a self-signed root CA and per-SNI leaf certificates for the
//! MITM reverse proxy (Hosts mode). Uses rcgen with an ECDSA P-256 key
//! (ring provider). The root cert is stored in the app data directory;
//! install/remove use certutil / PowerShell against the LocalMachine Root
//! store (requires elevation, like the original). Whether the system trusts
//! the certificate is answered in-process from the certificate stores.

use crate::paths;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;
use windows_sys::Win32::Security::Cryptography as crypt;

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
    /// Cached trust-store verdict, probed once per process (see `is_installed`).
    trusted: Arc<OnceLock<bool>>,
}

impl CertificateManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
            trusted: Arc::new(OnceLock::new()),
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
                let not_after =
                    SystemTime::UNIX_EPOCH + Duration::from_secs(dt.unix_timestamp().max(0) as u64);
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

        let not_after_sys =
            SystemTime::now() + Duration::from_secs((CERT_VALID_DAYS as u64) * 86400);
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
        let issuer = Issuer::from_ca_cert_der(&CertificateDer::from(rc.der.clone()), root_key)
            .map_err(|e| e.to_string())?;

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
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
        let cert = params
            .signed_by(&leaf_key, &issuer)
            .map_err(|e| e.to_string())?;
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

    /// Whether the system trusts **our** root certificate, i.e. whether the leaf
    /// certificates the MITM hands to clients would validate.
    ///
    /// This is a trust-store question, not a file question: the CA file may exist
    /// while a *different* certificate (or none at all) is installed, in which
    /// case every locally terminated TLS connection would fail with a certificate
    /// error. The stores are queried in-process through crypt32 (no
    /// `certutil`/PowerShell round trip) and the certificate is compared byte for
    /// byte, so a stale certificate with the same subject name does not count.
    ///
    /// Windows puts a certificate installed by the app (`certutil -addstore Root`,
    /// i.e. without `-user`) or by the certificate dialog into the *machine*
    /// store, so that store is checked first; a certificate placed in the *user*
    /// store is equally trusted and is accepted as well. Probed once per process:
    /// a certificate installed while the app is running is picked up on the next
    /// start, which is the hint the caller logs.
    pub fn is_installed(&self) -> bool {
        *self.trusted.get_or_init(|| match self.load() {
            Some(rc) => store_has_cert(&rc.der),
            None => false,
        })
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

/// Encoding flags of the certificates in the stores
/// (`X509_ASN_ENCODING | PKCS_7_ASN_ENCODING`).
const CERT_ENCODING: u32 = crypt::X509_ASN_ENCODING | crypt::PKCS_7_ASN_ENCODING;

/// `L"Root"`: the system certificate store to search (`pvPara` of
/// `CERT_STORE_PROV_SYSTEM_W`).
const ROOT_STORE_W: [u16; 5] = [b'R' as u16, b'o' as u16, b'o' as u16, b't' as u16, 0];

/// Whether any Windows certificate store holds a certificate whose DER encoding
/// equals `der`.
///
/// `CERT_FIND_ANY` walks the store certificate by certificate and every DER is
/// compared with `der`, so nothing but the exact certificate counts.
fn store_has_cert(der: &[u8]) -> bool {
    if der.is_empty() {
        return false;
    }
    for location in [
        crypt::CERT_SYSTEM_STORE_LOCAL_MACHINE,
        crypt::CERT_SYSTEM_STORE_CURRENT_USER,
    ] {
        if let Some(store) = StoreHandle::open(location) {
            if store.contains(der) {
                return true;
            }
        }
    }
    false
}

/// An open certificate store handle, closed on drop.
struct StoreHandle(crypt::HCERTSTORE);

impl StoreHandle {
    /// Open a system store (`Root`) in the given location
    /// (`CERT_SYSTEM_STORE_LOCAL_MACHINE` / `CERT_SYSTEM_STORE_CURRENT_USER`).
    ///
    /// `CERT_STORE_READONLY_FLAG` is required: without it crypt32 opens the
    /// machine store for writing as well and fails with `ERROR_ACCESS_DENIED`
    /// when the process is not elevated, which would leave the trust query
    /// unanswered for every non-admin run.
    fn open(location: u32) -> Option<Self> {
        // SAFETY: `CERT_STORE_PROV_SYSTEM_W` selects the system-store provider,
        // so `pvPara` is read as the wide store name `L"Root"` and `dwFlags` as
        // the store location; the null handle is checked below.
        let store = unsafe {
            crypt::CertOpenStore(
                crypt::CERT_STORE_PROV_SYSTEM_W,
                CERT_ENCODING,
                0,
                location | crypt::CERT_STORE_READONLY_FLAG,
                ROOT_STORE_W.as_ptr().cast(),
            )
        };
        if store.is_null() {
            None
        } else {
            Some(Self(store))
        }
    }

    /// Whether the store holds a certificate whose DER encoding equals `der`.
    fn contains(&self, der: &[u8]) -> bool {
        // `CertFindCertificateInStore` releases the context handed back as
        // `pPrevCertContext` itself ("This function frees the CERT_CONTEXT
        // referenced by non-NULL values of this parameter"), so only the context
        // that ends the walk may be freed here. Freeing `prev` as well would
        // release the same context twice and corrupt the heap.
        let mut prev: *const crypt::CERT_CONTEXT = std::ptr::null();
        loop {
            // SAFETY: `prev` is null on the first iteration and otherwise the
            // context returned by the previous iteration, which the callee owns
            // from here on; a null return is checked below.
            let ctx = unsafe {
                crypt::CertFindCertificateInStore(
                    self.0,
                    CERT_ENCODING,
                    0,
                    crypt::CERT_FIND_ANY,
                    std::ptr::null(),
                    prev,
                )
            };
            if ctx.is_null() {
                return false;
            }
            prev = ctx;
            // SAFETY: `ctx` points to a live `CERT_CONTEXT` whose
            // `pbCertEncoded` buffer holds `cbCertEncoded` readable bytes.
            let same = unsafe {
                let c = &*ctx;
                !c.pbCertEncoded.is_null()
                    && c.cbCertEncoded as usize == der.len()
                    && std::slice::from_raw_parts(c.pbCertEncoded, der.len()) == der
            };
            if same {
                // SAFETY: `prev` is the context just examined and the walk ends
                // here, so it is the caller's to release.
                unsafe { crypt::CertFreeCertificateContext(prev) };
                return true;
            }
        }
    }
}

impl Drop for StoreHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` comes from `CertOpenStore` and is not used afterwards.
        unsafe { crypt::CertCloseStore(self.0, 0) };
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A DER that no store holds must not be reported as installed.
    #[test]
    fn store_does_not_report_an_unknown_certificate() {
        assert!(!store_has_cert(&[]));
        assert!(!store_has_cert(&[0x30, 0x00]));
    }

    /// Reads the DER of one certificate the given store really holds, so the
    /// lookup can be checked against a certificate the machine has.
    fn first_cert_der(location: u32) -> Option<Vec<u8>> {
        let store = StoreHandle::open(location)?;
        // SAFETY: a null `pPrevCertContext` starts the walk; the returned
        // context is released below.
        let ctx = unsafe {
            crypt::CertFindCertificateInStore(
                store.0,
                CERT_ENCODING,
                0,
                crypt::CERT_FIND_ANY,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if ctx.is_null() {
            return None;
        }
        // SAFETY: `ctx` is live and `pbCertEncoded` holds `cbCertEncoded` bytes.
        let der = unsafe {
            let c = &*ctx;
            std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize).to_vec()
        };
        // SAFETY: the walk stops here, so this context is the caller's to free.
        unsafe { crypt::CertFreeCertificateContext(ctx) };
        Some(der)
    }

    /// The lookup has to find certificates the machine really has, otherwise even
    /// an installed certificate would be reported as untrusted, and the match has
    /// to be on the encoding rather than on the subject name.
    #[test]
    fn store_finds_certificates_the_machine_has() {
        let der = first_cert_der(crypt::CERT_SYSTEM_STORE_LOCAL_MACHINE)
            .or_else(|| first_cert_der(crypt::CERT_SYSTEM_STORE_CURRENT_USER))
            .expect("no certificate in the Windows root stores");
        assert!(store_has_cert(&der));
        let mut altered = der.clone();
        altered[10] ^= 0xff;
        assert!(!store_has_cert(&altered));
    }

    /// Repeated walks must not corrupt the heap: `CertFindCertificateInStore`
    /// releases the context passed as `pPrevCertContext` itself, so releasing it
    /// a second time would be a double free.
    #[test]
    fn repeated_store_lookups_stay_clean() {
        let der = first_cert_der(crypt::CERT_SYSTEM_STORE_LOCAL_MACHINE)
            .expect("no certificate in the machine root store");
        for _ in 0..200 {
            assert!(store_has_cert(&der));
            assert!(!store_has_cert(&[0x30, 0x00]));
        }
    }
}

//! HTTPS for local domains.
//!
//! A literal self-signed certificate is close to useless here: every browser
//! shows a full-page interstitial, and `fetch()` to that origin fails with an
//! opaque network error you cannot click through. What actually works is a
//! local CA the machine already trusts, issuing a leaf per hostname.
//!
//! So we look for the mkcert root most developers already have installed and
//! trusted, and mint from that. Nothing new is added to the system trust store
//! unless the user explicitly asks for it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{CertificateParams, DnType, Issuer, KeyPair};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;

use crate::config::data_dir;

/// A local certificate authority we can issue from.
pub struct LocalCa {
    pub cert_pem: String,
    pub key_pem: String,
    /// Where it came from, for `ports doctor` to report.
    pub source: PathBuf,
    /// True when this is mkcert's root rather than one we generated.
    pub is_mkcert: bool,
}

/// Ask mkcert where it keeps its root, then fall back to the platform default.
///
/// Running the binary is the reliable route: `$CAROOT` can move it, and mkcert
/// itself is the authority on where it put things.
fn mkcert_root() -> Option<PathBuf> {
    if let Ok(output) = std::process::Command::new("mkcert").arg("-CAROOT").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }

    // mkcert may be uninstalled while its trusted root remains in the keychain,
    // which is still perfectly usable.
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let candidate = if cfg!(target_os = "macos") {
        home.join("Library/Application Support/mkcert")
    } else {
        home.join(".local/share/mkcert")
    };
    candidate.exists().then_some(candidate)
}

fn read_ca_at(dir: &Path, is_mkcert: bool) -> Option<LocalCa> {
    let cert_pem = std::fs::read_to_string(dir.join("rootCA.pem")).ok()?;
    let key_pem = std::fs::read_to_string(dir.join("rootCA-key.pem")).ok()?;
    Some(LocalCa {
        cert_pem,
        key_pem,
        source: dir.to_path_buf(),
        is_mkcert,
    })
}

/// Where a CA we generated ourselves lives.
pub fn own_ca_dir() -> PathBuf {
    data_dir().join("ca")
}

/// Find a CA to issue from: mkcert's if present, else our own if we made one.
pub fn find_ca() -> Option<LocalCa> {
    if let Some(root) = mkcert_root() {
        if let Some(ca) = read_ca_at(&root, true) {
            return Some(ca);
        }
    }
    read_ca_at(&own_ca_dir(), false)
}

/// Generate a CA of our own. Only used when no mkcert root exists.
pub fn generate_ca() -> anyhow::Result<LocalCa> {
    let mut params = CertificateParams::new(Vec::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, "ports local CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "ports");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];

    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;

    let dir = own_ca_dir();
    std::fs::create_dir_all(&dir)?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();
    std::fs::write(dir.join("rootCA.pem"), &cert_pem)?;
    std::fs::write(dir.join("rootCA-key.pem"), &key_pem)?;

    // The private key of a trusted root: readable by nobody else.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            dir.join("rootCA-key.pem"),
            std::fs::Permissions::from_mode(0o600),
        );
    }

    Ok(LocalCa {
        cert_pem,
        key_pem,
        source: dir,
        is_mkcert: false,
    })
}

/// Issue a leaf certificate for one hostname.
pub fn issue_leaf(ca: &LocalCa, hostname: &str) -> anyhow::Result<(String, String)> {
    let ca_key = KeyPair::from_pem(&ca.key_pem)?;
    let issuer = Issuer::from_ca_cert_pem(&ca.cert_pem, ca_key)?;

    let mut params = CertificateParams::new(vec![hostname.to_string()])?;
    params.distinguished_name.push(DnType::CommonName, hostname);
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

    let leaf_key = KeyPair::generate()?;
    let leaf = params.signed_by(&leaf_key, &issuer)?;

    Ok((leaf.pem(), leaf_key.serialize_pem()))
}

fn certs_dir() -> PathBuf {
    data_dir().join("certs")
}

/// Mints leaves on demand and remembers them.
///
/// Certificates are cached on disk as well as in memory so a restarted daemon
/// does not hand the browser a different certificate for the same name, which
/// looks exactly like an attack.
pub struct CertStore {
    ca: LocalCa,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertStore {
    pub fn new(ca: LocalCa) -> Self {
        Self {
            ca,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn load_or_issue(&self, hostname: &str) -> anyhow::Result<Arc<CertifiedKey>> {
        let dir = certs_dir();
        let cert_path = dir.join(format!("{hostname}.pem"));
        let key_path = dir.join(format!("{hostname}-key.pem"));

        let (cert_pem, key_pem) = match (
            std::fs::read_to_string(&cert_path),
            std::fs::read_to_string(&key_path),
        ) {
            (Ok(cert), Ok(key)) => (cert, key),
            _ => {
                let (cert, key) = issue_leaf(&self.ca, hostname)?;
                std::fs::create_dir_all(&dir)?;
                std::fs::write(&cert_path, &cert)?;
                std::fs::write(&key_path, &key)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &key_path,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
                (cert, key)
            }
        };

        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()?;
        let key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut key_pem.as_bytes())?
                .ok_or_else(|| anyhow::anyhow!("no private key in {}", key_path.display()))?;

        let signing_key = tokio_rustls::rustls::crypto::ring::sign::any_supported_type(&key)?;
        Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
    }

    pub fn get(&self, hostname: &str) -> Option<Arc<CertifiedKey>> {
        // A hostname arrives from an untrusted ClientHello and becomes a file
        // path; anything that could escape the directory is refused.
        if hostname.is_empty()
            || hostname.len() > 253
            || hostname.contains('/')
            || hostname.contains('\\')
            || hostname.contains("..")
            || !hostname
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return None;
        }

        if let Some(found) = self.cache.lock().ok()?.get(hostname) {
            return Some(Arc::clone(found));
        }

        let issued = self.load_or_issue(hostname).ok()?;
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(hostname.to_string(), Arc::clone(&issued));
        }
        Some(issued)
    }
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore")
            .field("ca", &self.ca.source)
            .finish()
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // No SNI means we cannot know which name to issue for. Every browser
        // sends it; a bare IP connection does not, and has no business here.
        self.get(client_hello.server_name()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::FromDer;

    /// A throwaway CA, so the tests never touch the real one.
    fn test_ca() -> LocalCa {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "test CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];

        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();

        LocalCa {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            source: PathBuf::from("/tmp/test-ca"),
            is_mkcert: false,
        }
    }

    #[test]
    fn issues_a_leaf_for_a_hostname() {
        let ca = test_ca();
        let (cert_pem, key_pem) = issue_leaf(&ca, "myapp.localhost").unwrap();

        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.contains("PRIVATE KEY"));

        // The name must be in the SAN, not only the CN: browsers have ignored
        // commonName for host matching for years.
        let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let (_, parsed) = x509_parser::prelude::X509Certificate::from_der(&der).unwrap();
        let san = parsed
            .subject_alternative_name()
            .unwrap()
            .expect("leaf should carry a SAN");
        let names: Vec<String> = san
            .value
            .general_names
            .iter()
            .filter_map(|n| match n {
                x509_parser::prelude::GeneralName::DNSName(dns) => Some(dns.to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(names, vec!["myapp.localhost"]);
    }

    #[test]
    fn the_leaf_is_signed_by_the_ca_rather_than_itself() {
        let ca = test_ca();
        let (cert_pem, _) = issue_leaf(&ca, "myapp.localhost").unwrap();

        let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let (_, leaf) = x509_parser::prelude::X509Certificate::from_der(&der).unwrap();

        let issuer = leaf.issuer().to_string();
        assert!(issuer.contains("test CA"), "unexpected issuer: {issuer}");
        assert_ne!(
            leaf.subject().to_string(),
            issuer,
            "a self-signed leaf would defeat the whole point"
        );
    }

    #[test]
    fn multi_level_names_get_their_own_certificate() {
        let ca = test_ca();
        // A wildcard cannot cover api.myapp.localhost, so each name is issued
        // for individually.
        let (cert_pem, _) = issue_leaf(&ca, "api.myapp.localhost").unwrap();
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn rejects_hostnames_that_could_escape_the_cert_directory() {
        let store = CertStore::new(test_ca());
        for hostile in [
            "../../etc/passwd",
            "a/b",
            "a\\b",
            "..",
            "",
            "name with spaces",
        ] {
            assert!(
                store.get(hostile).is_none(),
                "{hostile:?} should have been refused"
            );
        }
    }

    #[test]
    fn generating_our_own_ca_produces_a_usable_issuer() {
        // Isolate from the real data dir.
        let temp = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_DATA_HOME", temp.path());

        let ca = generate_ca().expect("should generate a CA");
        assert!(ca.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(!ca.is_mkcert);

        // It must actually be able to sign.
        let (leaf, _) = issue_leaf(&ca, "myapp.localhost").unwrap();
        assert!(leaf.starts_with("-----BEGIN CERTIFICATE-----"));

        std::env::remove_var("XDG_DATA_HOME");
    }
}

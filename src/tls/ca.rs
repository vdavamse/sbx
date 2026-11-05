//! The per-run certificate authority (issue #17, D3).
//!
//! 1. **One CA per `sbx run`.** Generated in memory at startup: ECDSA P-256,
//!    a random serial (derived from a freshly generated public key), subject
//!    `CN = sbx per-run CA`. Basic constraints `CA:TRUE, pathlen 0`; key usages
//!    `keyCertSign` + `cRLSign` only. Name constraints permit exactly the
//!    policy's `network.mitm_hosts`: each host is a permitted DNS subtree and
//!    its subdomains (`.host`) an excluded one, so even a leaked CA key could
//!    vouch only for those exact names.
//! 2. **Short validity.** The window starts five minutes in the past (clock
//!    skew) and ends `run timeout + 1 h` (for a `--keep-alive` session, its max
//!    lifetime + 1 h), capped at 24 h. Leaves share the
//!    window, so nothing outlives the run by much.
//! 3. **The key never leaves the process.** It lives inside [`RunCa`] (the
//!    rcgen `Issuer`) and is never serialized, written to disk, mounted, put
//!    in an env var or argv, or printed: [`RunCa`]'s `Debug` redacts it, and
//!    the only export is [`RunCa::cert_pem`] (the certificate alone). The
//!    sandbox sees the certificate; it cannot see the key.
//! 4. **Leaves are minted on demand.** [`RunCa::leaf`] mints one certificate
//!    for one SNI name (SAN = that name, `serverAuth`, same window), with a
//!    fresh key that is handed straight to rustls and then dropped with the
//!    server config. Callers cache per host (see `super::Terminator`).

use std::fmt;
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::policy::Domain;

/// The CA's validity ceiling (issue #17, D3): a day, whatever the run lasts.
const CA_MAX_VALIDITY: Duration = Duration::from_secs(24 * 60 * 60);
/// Added to the run timeout so the CA outlives the run's teardown.
const RUN_SLACK: Duration = Duration::from_secs(60 * 60);
/// Backdating against clock skew between sbx and the sandbox client.
const CLOCK_SKEW: TimeDuration = TimeDuration::minutes(5);

/// The per-run CA: certificate plus the signing key that stays in memory.
pub struct RunCa {
    issuer: Issuer<'static, KeyPair>,
    cert: Certificate,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

impl fmt::Debug for RunCa {
    // The key is never printed: a Debug line in a log must not be a key leak.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunCa")
            .field("key", &"<redacted>")
            .field("not_after", &self.not_after)
            .finish()
    }
}

impl RunCa {
    /// Generate the run's CA for the given terminated hosts. `run_timeout` is
    /// the effective run timeout (the validity window is derived from it).
    pub fn generate(hosts: &[Domain], run_timeout: Duration) -> Result<Self, String> {
        if hosts.is_empty() {
            return Err("a per-run CA needs at least one terminated host".to_owned());
        }
        let validity = run_timeout.saturating_add(RUN_SLACK).min(CA_MAX_VALIDITY);
        let now = OffsetDateTime::now_utc();
        let not_before = now - CLOCK_SKEW;
        let not_after =
            now + TimeDuration::seconds(i64::try_from(validity.as_secs()).unwrap_or(i64::MAX));

        let key =
            KeyPair::generate().map_err(|err| format!("cannot generate the CA key: {err}"))?;
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|err| format!("cannot build the CA parameters: {err}"))?;
        params
            .distinguished_name
            .push(DnType::CommonName, "sbx per-run CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: hosts
                .iter()
                .map(|host| GeneralSubtree::DnsName(host.as_str().to_owned()))
                .collect(),
            // A dNSName subtree also covers subdomains (RFC 5280 §4.2.1.10), so
            // exclude them: the CA vouches for exactly the mitm hosts (PR #64 m1).
            excluded_subtrees: hosts
                .iter()
                .map(|host| GeneralSubtree::DnsName(format!(".{}", host.as_str())))
                .collect(),
        });
        params.serial_number = Some(serial_for(&key));
        params.not_before = not_before;
        params.not_after = not_after;
        let cert = params
            .self_signed(&key)
            .map_err(|err| format!("cannot self-sign the CA: {err}"))?;
        let issuer = Issuer::new(params, key);
        Ok(Self {
            issuer,
            cert,
            not_before,
            not_after,
        })
    }

    /// The CA certificate as PEM. The ONLY export of this type: it carries
    /// no key material.
    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }

    /// The CA certificate DER (for the upstream-trust seam and tests).
    pub fn cert_der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    /// Mint a leaf for one terminated host: `(chain, key)` where the chain is
    /// the leaf followed by the CA. The key is returned to the caller only
    /// to build a rustls server config; it is not retained here.
    pub(crate) fn leaf(
        &self,
        host: &Domain,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
        let key =
            KeyPair::generate().map_err(|err| format!("cannot generate a leaf key: {err}"))?;
        let mut params = CertificateParams::new(vec![host.as_str().to_owned()]).map_err(|err| {
            format!(
                "cannot build the leaf parameters for {}: {err}",
                host.as_str()
            )
        })?;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.serial_number = Some(serial_for(&key));
        params.not_before = self.not_before;
        params.not_after = self.not_after;
        let leaf = params
            .signed_by(&key, &self.issuer)
            .map_err(|err| format!("cannot sign the leaf for {}: {err}", host.as_str()))?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        Ok((vec![leaf.der().clone(), self.cert.der().clone()], key_der))
    }
}

/// A 16-byte positive serial taken from a fresh key's public point: unique
/// per certificate, with no separate RNG dependency (the key itself is the
/// randomness source rcgen already uses).
fn serial_for(key: &KeyPair) -> SerialNumber {
    let mut bytes: Vec<u8> = key
        .public_key_raw()
        .iter()
        .skip(1)
        .take(16)
        .copied()
        .collect();
    if let Some(first) = bytes.first_mut() {
        *first &= 0x7f;
    }
    SerialNumber::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::RootCertStore;
    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{ServerName, UnixTime};

    use super::*;

    fn domain(raw: &str) -> Domain {
        Domain::parse(raw).expect("fixture name")
    }

    fn verifier_for(ca: &RunCa) -> Arc<WebPkiServerVerifier> {
        let mut roots = RootCertStore::empty();
        roots
            .add(ca.cert_der())
            .expect("the CA is a valid trust anchor");
        WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .expect("verifier")
    }

    #[test]
    fn ca_pem_is_a_certificate_and_never_key_material() {
        let ca = RunCa::generate(&[domain("api.example.com")], Duration::from_secs(60))
            .expect("generate");
        let pem = ca.cert_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"), "{pem}");
        assert!(!pem.contains("PRIVATE KEY"));
        let debug = format!("{ca:?}");
        assert!(!debug.contains("PRIVATE"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }

    #[test]
    fn validity_is_timeout_plus_slack_capped_at_a_day() {
        let hosts = [domain("api.example.com")];
        // 60 s run: timeout + 1 h, plus the 5-minute backdating.
        let short = RunCa::generate(&hosts, Duration::from_secs(60)).expect("generate");
        assert_eq!(
            short.not_after - short.not_before,
            TimeDuration::seconds(60 * 60 + 60) + TimeDuration::minutes(5)
        );
        // A ten-day run is capped at 24 h (+ the backdating).
        let long = RunCa::generate(&hosts, Duration::from_secs(10 * 24 * 3600)).expect("generate");
        assert_eq!(
            long.not_after - long.not_before,
            TimeDuration::hours(24) + TimeDuration::minutes(5)
        );
    }

    #[test]
    fn leaves_verify_under_the_run_ca_and_respect_name_constraints() {
        let ca = RunCa::generate(&[domain("api.example.com")], Duration::from_secs(60))
            .expect("generate");
        let verifier = verifier_for(&ca);
        let host = domain("api.example.com");
        let (chain, _key) = ca.leaf(&host).expect("leaf");
        assert_eq!(chain.len(), 2, "leaf then CA");
        verifier
            .verify_server_cert(
                &chain[0],
                &chain[1..],
                &ServerName::try_from("api.example.com").expect("name"),
                &[],
                UnixTime::now(),
            )
            .expect("the permitted leaf verifies");

        // A leaf minted for a name outside the permitted subtree must not
        // verify: the CA's name constraints hold even for a forged leaf.
        let (outside, _key) = ca.leaf(&domain("evil.example.com")).expect("leaf");
        assert!(
            verifier
                .verify_server_cert(
                    &outside[0],
                    &outside[1..],
                    &ServerName::try_from("evil.example.com").expect("name"),
                    &[],
                    UnixTime::now(),
                )
                .is_err(),
            "a name outside the constraints must be refused"
        );

        // Nor may a subdomain of a permitted host (the excluded subtrees).
        let (sub, _key) = ca.leaf(&domain("x.api.example.com")).expect("leaf");
        assert!(
            verifier
                .verify_server_cert(
                    &sub[0],
                    &sub[1..],
                    &ServerName::try_from("x.api.example.com").expect("name"),
                    &[],
                    UnixTime::now(),
                )
                .is_err(),
            "a subdomain of a permitted host must be refused"
        );
    }
}

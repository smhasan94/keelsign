//! The device's verify configuration: policy, trusted keys and backend.

use keelsign_verify::{DefaultBackend, Ed25519Key, Policy, TrustedKey};

/// What an updater accepts: the [`Policy`], up to `N` trusted post-quantum keys, up to `E`
/// trusted Ed25519 keys (the classical half of hybrid images) and the post-quantum
/// backend.
///
/// The keys are borrowed (typically from flash) and checked once, when an updater is
/// built ([`Error::KeySet`](crate::Error::KeySet)). A `Config` can be a `const`:
///
/// ```
/// use keelsign_embassy::{Algorithm, Config, Policy, TrustedKey};
///
/// static LMS_KEY: [u8; 60] = [0; 60]; // the device's LMS/HSS public key
/// const CONFIG: Config<'static, 1> = Config::new(
///     Policy::PqOnly,
///     [TrustedKey { algorithm: Algorithm::LmsHss, public_key: &LMS_KEY }],
///     [],
/// );
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Config<'k, const N: usize, const E: usize = 0> {
    /// Which signatures an image needs.
    pub policy: Policy,
    /// The trusted post-quantum public keys (LMS/HSS, ML-DSA-44/65).
    pub pq_keys: [TrustedKey<'k>; N],
    /// The trusted Ed25519 public keys, for [`Policy::ClassicalOnly`] and
    /// [`Policy::Hybrid`] (they need the `ed25519` feature).
    pub ed25519_keys: [Ed25519Key<'k>; E],
    /// The post-quantum backend: [`DefaultBackend::new`] unless [`Config::cnsa_2_0`].
    pub backend: DefaultBackend,
}

impl<'k, const N: usize, const E: usize> Config<'k, N, E> {
    /// A configuration with [`DefaultBackend::new`] (LMS/HSS up to two levels, and
    /// ML-DSA-44/65 with the `ml-dsa` feature).
    pub const fn new(
        policy: Policy,
        pq_keys: [TrustedKey<'k>; N],
        ed25519_keys: [Ed25519Key<'k>; E],
    ) -> Self {
        Self {
            policy,
            pq_keys,
            ed25519_keys,
            backend: DefaultBackend::new(),
        }
    }

    /// The same configuration with the strict [`DefaultBackend::cnsa_2_0`] backend
    /// (single-tree LMS only, no ML-DSA).
    #[must_use]
    pub const fn cnsa_2_0(self) -> Self {
        Self {
            backend: DefaultBackend::cnsa_2_0(),
            ..self
        }
    }
}

#[cfg(test)]
mod tests {
    // Host test code, not no_std firmware: failing a test with a message is the point.
    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )]

    use keelsign_verify::Algorithm;

    use super::*;

    static KEY: [u8; 60] = [0; 60];
    static ED_KEY: [u8; 32] = [7; 32];

    const DEFAULT: Config<'static, 1, 1> = Config::new(
        Policy::Hybrid,
        [TrustedKey {
            algorithm: Algorithm::LmsHss,
            public_key: &KEY,
        }],
        [Ed25519Key {
            public_key: &ED_KEY,
        }],
    );
    const STRICT: Config<'static, 1, 1> = DEFAULT.cnsa_2_0();

    #[test]
    fn config_is_constructible_in_a_const() {
        assert_eq!(DEFAULT.policy, Policy::Hybrid);
        assert_eq!(DEFAULT.backend, DefaultBackend::new());
        assert_eq!(STRICT.backend, DefaultBackend::cnsa_2_0());
        assert_eq!(STRICT.policy, DEFAULT.policy);
        assert_eq!(STRICT.pq_keys, DEFAULT.pq_keys);
        assert_eq!(STRICT.ed25519_keys, DEFAULT.ed25519_keys);
    }
}

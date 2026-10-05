//! SHA-55 TP3 / TP4 / AC2 on the host: the updaters mark the DFU image for swap if and
//! only if keelsign-verify accepts it, verification never writes, and a reset at any
//! point of marking leaves the state `Boot` or `Swap`. Mock flash in `common`.

// Host test code, not no_std firmware: failing a test with a message is the point.
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use std::cell::RefCell;

use common::*;
use keelsign_embassy::{
    Algorithm, AlignedBuffer, Config, ConfigError, DEFAULT_CHUNK_LEN, Error, Layout, Policy, State,
    TrustedKey,
};
use keelsign_verify::{ImageError, KeySetError};
use policy_kat::{Expect, Fixture, POLICY_TARGET};

const LMS_IMAGE: &str = "keelsign-lms-m32-h5.bin";
const LARGE_IMAGE: &[u8] = include_bytes!("../../tests/fixtures/images/mcuboot-ed25519-200k.bin");

fn fixture() -> Fixture<'static> {
    Fixture::parse(POLICY_TARGET).unwrap()
}

fn image(name: &str) -> &'static [u8] {
    policy_kat::image(name).unwrap_or_else(|| panic!("no image {name}"))
}

/// The key the LMS image is signed with.
fn lms_key() -> TrustedKey<'static> {
    pq_key(&fixture().case(LMS_IMAGE).unwrap()).unwrap()
}

/// `PqOnly` with the LMS image's key trusted.
fn lms_config() -> Config<'static, 1> {
    Config::new(Policy::PqOnly, [lms_key()], [])
}

#[test]
fn blocking_valid_lms_image_is_verified_and_marked_swap() {
    let (result, flash) = mark_blocking(flash_with(image(LMS_IMAGE)), &lms_config());
    let verified = result.unwrap();
    assert_eq!(verified.policy, Policy::PqOnly);
    assert_eq!(verified.pq_key, Some(lms_key()));
    assert_eq!(verified.image_len, 3408);
    assert_eq!(state_word(&flash), [SWAP_MAGIC; 4]);
    assert!(mutations_only_in_state(&flash.ops));
    // The state reads back as Swap through a fresh updater (after a reset).
    let shared = Shared::new(RefCell::new(flash));
    let mut aligned = AlignedBuffer([0u8; WRITE_SIZE]);
    let mut updater = blocking_updater(&shared, &mut aligned.0, &lms_config()).unwrap();
    assert_eq!(updater.get_state().unwrap(), State::Swap);
}

/// Checks a rejected image: `expected` error, the state partition untouched and nothing
/// written or erased anywhere.
fn assert_rejected_and_not_marked(
    result: Result<keelsign_embassy::VerifiedImage<'_>, Error>,
    flash: &Flash,
    expected: keelsign_verify::Error,
) {
    assert_eq!(result.err(), Some(Error::Rejected(expected)));
    assert_eq!(state_word(flash), [0xFF; 4], "state still erased (Boot)");
    assert!(
        flash.ops.iter().all(|op| !op.mutates()),
        "nothing written: {:?}",
        flash
            .ops
            .iter()
            .filter(|op| op.mutates())
            .collect::<Vec<_>>()
    );
}

#[test]
fn blocking_tampered_body_and_signature_are_rejected_and_not_marked() {
    let fixture = fixture();
    for (name, expected) in [
        (
            "keelsign-hybrid-bad-body.bin",
            keelsign_verify::Error::Image(ImageError::DigestMismatch),
        ),
        (
            "keelsign-hybrid-bad-pq.bin",
            keelsign_verify::Error::SignatureInvalid,
        ),
    ] {
        let key = pq_key(&fixture.case(name).unwrap()).unwrap();
        let config = Config::new(Policy::PqOnly, [key], []);
        let (result, flash) = mark_blocking(flash_with(image(name)), &config);
        assert_rejected_and_not_marked(result, &flash, expected);
    }
    // A valid image with one body byte flipped in the slot.
    let mut flash = flash_with(image(LMS_IMAGE));
    flash.mem[DFU_OFFSET as usize + 0x200] ^= 0x01;
    let (result, flash) = mark_blocking(flash, &lms_config());
    assert_rejected_and_not_marked(
        result,
        &flash,
        keelsign_verify::Error::Image(ImageError::DigestMismatch),
    );
}

#[test]
fn blocking_untrusted_key_is_rejected_and_not_marked() {
    // The HSS image is signed with another key than the one trusted.
    let (result, flash) = mark_blocking(
        flash_with(image("keelsign-hss2-m32-h5h5.bin")),
        &lms_config(),
    );
    assert_rejected_and_not_marked(result, &flash, keelsign_verify::Error::KeyNotTrusted);
}

/// SHA-46's policy matrix through the blocking updater: every case under every policy
/// gives keelsign-verify's verdict, and the state is `Swap` exactly for `Ok`.
#[test]
fn every_policy_matrix_case_marks_iff_the_verdict_is_ok() {
    let ml_dsa = Algorithm::MlDsa44.is_enabled();
    let mut cells = 0;
    for case in fixture().cases() {
        let case = case.unwrap();
        for &policy in Policy::ALL {
            let expect = case.expect(policy, ml_dsa).unwrap();
            let flash = flash_with(image(case.name));
            let (result, flash) = match pq_key(&case) {
                Some(key) => mark_blocking(flash, &Config::new(policy, [key], ed25519_keys())),
                None => mark_blocking(flash, &Config::<0, 1>::new(policy, [], ed25519_keys())),
            };
            let cell = format!("{} under {policy:?}", case.name);
            assert_eq!(verdict(&result), Some(expect), "{cell}: {result:?}");
            if expect == Expect::Ok {
                assert_eq!(state_word(&flash), [SWAP_MAGIC; 4], "{cell}: marked");
                assert!(mutations_only_in_state(&flash.ops), "{cell}");
            } else {
                assert_eq!(state_word(&flash), [0xFF; 4], "{cell}: not marked");
                assert!(flash.ops.iter().all(|op| !op.mutates()), "{cell}");
            }
            cells += 1;
        }
    }
    assert_eq!(cells, policy_kat::TARGET_CASES * 3);
}

/// SHA-69 AC1 / TP1 on the host (the mock-flash mirror of docs/embassy.md P5): under
/// `Policy::Hybrid`, with the image's LMS/HSS key and the Ed25519 test key trusted, both
/// updaters mark the good HSS L=1 and L=2 hybrid images for swap and reject every image
/// with either half tampered or missing, naming the half, without writing anything.
#[test]
fn hybrid_lms_cases_mark_iff_both_halves_verify() {
    use keelsign_verify::Ed25519Error;
    let fixture = fixture();
    let cases: [(&str, Option<keelsign_verify::Error>); 10] = [
        ("keelsign-hybrid-ed25519-lms.bin", None),
        ("keelsign-hybrid-ed25519-hss2.bin", None),
        (
            "keelsign-hybrid-bad-ed25519.bin",
            Some(keelsign_verify::Error::Ed25519(
                Ed25519Error::SignatureInvalid,
            )),
        ),
        (
            "keelsign-hybrid-hss2-bad-ed25519.bin",
            Some(keelsign_verify::Error::Ed25519(
                Ed25519Error::SignatureInvalid,
            )),
        ),
        (
            "keelsign-hybrid-bad-pq.bin",
            Some(keelsign_verify::Error::SignatureInvalid),
        ),
        (
            "keelsign-hybrid-hss2-bad-pq.bin",
            Some(keelsign_verify::Error::SignatureInvalid),
        ),
        (
            "keelsign-hybrid-hss2-bad-top-level.bin",
            Some(keelsign_verify::Error::SignatureInvalid),
        ),
        (
            "keelsign-hybrid-missing-pq.bin",
            Some(keelsign_verify::Error::MissingPqSignature),
        ),
        (
            "keelsign-hybrid-hss2-missing-pq.bin",
            Some(keelsign_verify::Error::MissingPqSignature),
        ),
        (
            LMS_IMAGE,
            Some(keelsign_verify::Error::Ed25519(Ed25519Error::Missing)),
        ),
    ];
    for (name, expected) in cases {
        let key = pq_key(&fixture.case(name).unwrap()).unwrap();
        let config = Config::new(Policy::Hybrid, [key], ed25519_keys());
        let (blocking, b_flash) = mark_blocking(flash_with(image(name)), &config);
        let (asynchronous, a_flash) = mark_async(flash_with(image(name)), &config);
        assert_eq!(asynchronous, blocking, "{name}: async == blocking");
        assert_eq!(a_flash.mem, b_flash.mem, "{name}: the same flash contents");
        match expected {
            None => {
                let verified = blocking.unwrap_or_else(|e| panic!("{name}: {e:?}"));
                assert_eq!(verified.policy, Policy::Hybrid, "{name}");
                assert_eq!(verified.pq_key, Some(key), "{name}");
                assert_eq!(
                    verified.ed25519_key,
                    Some(ed25519_keys()[0]),
                    "{name}: the Ed25519 test key"
                );
                assert_eq!(state_word(&b_flash), [SWAP_MAGIC; 4], "{name}: marked");
                assert!(mutations_only_in_state(&b_flash.ops), "{name}");
            }
            Some(error) => assert_rejected_and_not_marked(blocking, &b_flash, error),
        }
    }
}

#[test]
fn large_image_verifies_from_a_256k_slot() {
    assert_eq!(LARGE_IMAGE.len(), 205_579);
    let config = Config::<0, 1>::new(Policy::ClassicalOnly, [], ed25519_keys());
    let (result, flash) = mark_blocking(flash_with(LARGE_IMAGE), &config);
    let verified = result.unwrap();
    assert_eq!(verified.image_len, 205_579);
    assert_eq!(state_word(&flash), [SWAP_MAGIC; 4]);
    // The body was hashed in DEFAULT_CHUNK_LEN reads, all inside the slot.
    let reads: Vec<_> = flash
        .ops
        .iter()
        .filter(|op| matches!(op, Op::Read { .. }))
        .filter(|op| op.range().0 >= DFU_OFFSET)
        .collect();
    assert!(reads.len() > 204_800 / DEFAULT_CHUNK_LEN);
    assert!(reads.iter().all(|op| op.range().1 <= DFU_OFFSET + DFU_LEN));
}

#[test]
fn verify_performs_no_flash_writes_or_erases_and_marking_touches_only_the_state_partition() {
    let shared = Shared::new(RefCell::new(flash_with(image(LMS_IMAGE))));
    let mut aligned = [0u8; WRITE_SIZE];
    let config = lms_config();
    let mut tlv_buf = [0u8; 4096];
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    {
        let mut updater = blocking_updater(&shared, &mut aligned, &config).unwrap();
        updater.verify(&mut tlv_buf, &mut chunk).unwrap();
    }
    let ops = shared.lock(|f| f.borrow().ops.clone());
    assert!(!ops.is_empty());
    for op in &ops {
        let (from, to) = op.range();
        assert!(
            matches!(op, Op::Read { .. }) && from >= DFU_OFFSET && to <= DFU_OFFSET + DFU_LEN,
            "verify only reads the DFU slot: {op:?}"
        );
    }
    let verified_ops = ops.len();
    {
        let mut updater = blocking_updater(&shared, &mut aligned, &config).unwrap();
        updater
            .verify_and_mark_updated(&mut tlv_buf, &mut chunk)
            .unwrap();
    }
    let flash = shared.into_inner().into_inner();
    let marking = &flash.ops[verified_ops..];
    assert!(marking.iter().any(Op::mutates));
    assert!(mutations_only_in_state(marking), "{marking:?}");
    assert_eq!(state_word(&flash), [SWAP_MAGIC; 4]);
    // The DFU slot is byte-for-byte what was placed there.
    let mut expected = Flash::new();
    place(&mut expected, image(LMS_IMAGE));
    let dfu = DFU_OFFSET as usize..(DFU_OFFSET + DFU_LEN) as usize;
    assert_eq!(flash.mem[dfu.clone()], expected.mem[dfu]);
}

/// The state partition after `mark_booted`, as a device runs after a confirmed boot.
fn booted(mut flash: Flash) -> Flash {
    let shared = Shared::new(RefCell::new(flash));
    {
        let mut aligned = [0u8; WRITE_SIZE];
        let mut updater = blocking_updater(&shared, &mut aligned, &lms_config()).unwrap();
        updater.mark_booted().unwrap();
    }
    flash = shared.into_inner().into_inner();
    assert_eq!(state_word(&flash), [BOOT_MAGIC; 4]);
    flash.ops.clear();
    flash
}

#[test]
fn reset_at_any_point_during_mark_leaves_boot_or_swap() {
    for start in [
        flash_with(image(LMS_IMAGE)),
        booted(flash_with(image(LMS_IMAGE))),
    ] {
        for blocking in [true, false] {
            let mark = |flash: Flash| {
                if blocking {
                    mark_blocking(flash, &lms_config())
                } else {
                    mark_async(flash, &lms_config())
                }
            };
            // How many writes and erases a full mark takes from this state.
            let (result, done) = mark(start.clone());
            result.unwrap();
            let total = done.mutations();
            assert!(total >= 2, "marking erases and writes");
            for allowed in 0..=total {
                let mut flash = start.clone();
                flash.freeze_after = Some(allowed);
                let (result, mut flash) = mark(flash);
                if allowed < total {
                    assert_eq!(
                        result.err(),
                        Some(Error::Flash(
                            embedded_storage::nor_flash::NorFlashErrorKind::Other
                        )),
                        "power lost after {allowed} of {total} writes/erases"
                    );
                } else {
                    result.unwrap();
                }
                // Reset: power back, a fresh updater reads the state.
                flash.power_on();
                let shared = Shared::new(RefCell::new(flash));
                let mut aligned = [0u8; WRITE_SIZE];
                let mut updater = blocking_updater(&shared, &mut aligned, &lms_config()).unwrap();
                let state = updater.get_state().unwrap();
                assert!(
                    matches!(state, State::Boot | State::Swap),
                    "after {allowed} of {total}: {state:?}"
                );
                assert_eq!(
                    state == State::Swap,
                    allowed == total,
                    "after {allowed} of {total}"
                );
            }
        }
    }
}

/// The async updater gives the blocking updater's result, state and writes on every
/// policy-matrix cell.
#[test]
fn async_updater_matches_blocking_on_every_matrix_case() {
    let ml_dsa = Algorithm::MlDsa44.is_enabled();
    let mut cells = 0;
    for case in fixture().cases() {
        let case = case.unwrap();
        for &policy in Policy::ALL {
            let expect = case.expect(policy, ml_dsa).unwrap();
            let start = flash_with(image(case.name));
            let ((b_result, b_flash), (a_result, a_flash)) = match pq_key(&case) {
                Some(key) => {
                    let config = Config::new(policy, [key], ed25519_keys());
                    (
                        mark_blocking(start.clone(), &config),
                        mark_async(start, &config),
                    )
                }
                None => {
                    let config = Config::<0, 1>::new(policy, [], ed25519_keys());
                    (
                        mark_blocking(start.clone(), &config),
                        mark_async(start, &config),
                    )
                }
            };
            let cell = format!("{} under {policy:?}", case.name);
            assert_eq!(a_result, b_result, "{cell}");
            assert_eq!(verdict(&a_result), Some(expect), "{cell}");
            assert_eq!(state_word(&a_flash), state_word(&b_flash), "{cell}");
            assert_eq!(
                mutations(&a_flash.ops),
                mutations(&b_flash.ops),
                "{cell}: the same writes and erases"
            );
            assert_eq!(a_flash.mem, b_flash.mem, "{cell}: the same flash contents");
            cells += 1;
        }
    }
    assert_eq!(cells, policy_kat::TARGET_CASES * 3);
}

#[test]
fn not_accepted_by_caller_is_not_marked() {
    let shared = Shared::new(RefCell::new(flash_with(image(LMS_IMAGE))));
    let mut aligned = [0u8; WRITE_SIZE];
    let config = lms_config();
    let mut seen = None;
    {
        let mut updater = blocking_updater(&shared, &mut aligned, &config).unwrap();
        let mut tlv_buf = [0u8; 4096];
        let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
        let result = updater.verify_and_mark_updated_if(&mut tlv_buf, &mut chunk, |image| {
            seen = Some(image.version);
            false
        });
        assert_eq!(result.err(), Some(Error::NotAccepted));
        assert_eq!(updater.get_state().unwrap(), State::Boot);
    }
    let version = seen.expect("accept saw the verified image");
    assert_eq!(
        (
            version.major,
            version.minor,
            version.revision,
            version.build_num
        ),
        (1, 2, 3, 4)
    );
    let flash = shared.into_inner().into_inner();
    assert!(flash.ops.iter().all(|op| !op.mutates()));
    assert_eq!(state_word(&flash), [0xFF; 4]);
}

#[test]
fn pending_swap_is_bad_state_and_nothing_is_written() {
    // A first update is marked; a second request before the reset is refused.
    let (result, flash) = mark_blocking(flash_with(image(LMS_IMAGE)), &lms_config());
    result.unwrap();
    let mut flash = flash;
    flash.ops.clear();
    let (result, flash) = mark_blocking(flash, &lms_config());
    assert_eq!(result.err(), Some(Error::BadState));
    assert_eq!(state_word(&flash), [SWAP_MAGIC; 4]);
    // Only the state word was read: the DFU slot was not even verified.
    assert!(flash.ops.iter().all(|op| !op.mutates()));
    assert!(
        flash
            .ops
            .iter()
            .all(|op| op.range().1 <= STATE_OFFSET + STATE_LEN)
    );
}

#[test]
fn config_and_key_errors_are_reported_before_any_flash_access() {
    let shared = Shared::new(RefCell::new(flash_with(image(LMS_IMAGE))));
    // An LMS key of the wrong length.
    let bad_key = [TrustedKey {
        algorithm: Algorithm::LmsHss,
        public_key: &[0u8; 59],
    }];
    let mut aligned = [0u8; WRITE_SIZE];
    assert_eq!(
        blocking_updater(
            &shared,
            &mut aligned,
            &Config::new(Policy::PqOnly, bad_key, [])
        )
        .err(),
        Some(Error::KeySet(KeySetError::InvalidPublicKeyLength(
            Algorithm::LmsHss
        )))
    );
    // The same key twice.
    let twice = Config::new(Policy::PqOnly, [lms_key(), lms_key()], []);
    assert_eq!(
        blocking_updater(&shared, &mut aligned, &twice).err(),
        Some(Error::KeySet(KeySetError::DuplicateKeyId))
    );
    // An aligned buffer that is not the state flash's WRITE_SIZE.
    for len in [0, 1, WRITE_SIZE - 1, WRITE_SIZE + 1, 32] {
        let mut aligned = vec![0u8; len];
        assert_eq!(
            blocking_updater(&shared, &mut aligned, &lms_config()).err(),
            Some(Error::Config(ConfigError::AlignedBufferLen)),
            "aligned buffer of {len}"
        );
    }
    // An empty DFU partition.
    {
        let dfu =
            embassy_embedded_hal::flash::partition::BlockingPartition::new(&shared, DFU_OFFSET, 0);
        let state = embassy_embedded_hal::flash::partition::BlockingPartition::new(
            &shared,
            STATE_OFFSET,
            STATE_LEN,
        );
        let mut aligned = [0u8; WRITE_SIZE];
        assert_eq!(
            keelsign_embassy::BlockingUpdater::new(
                keelsign_embassy::FirmwareUpdaterConfig { dfu, state },
                &mut aligned,
                &lms_config(),
            )
            .err(),
            Some(Error::Config(ConfigError::DfuSlotEmpty))
        );
    }
    let flash = shared.into_inner().into_inner();
    assert!(flash.ops.is_empty(), "no flash access: {:?}", flash.ops);

    // The async updater checks the layout too, so embassy's partition and state-buffer
    // assertions cannot fire.
    let shared = AsyncShared::new(flash_with(image(LMS_IMAGE)));
    let cases = [
        (LAYOUT, WRITE_SIZE + 1, ConfigError::AlignedBufferLen),
        (
            Layout {
                dfu_len: 0,
                ..LAYOUT
            },
            WRITE_SIZE,
            ConfigError::DfuSlotEmpty,
        ),
        (
            Layout {
                dfu_offset: DFU_OFFSET + 4,
                ..LAYOUT
            },
            WRITE_SIZE,
            ConfigError::DfuUnaligned,
        ),
        (
            Layout {
                dfu_len: DFU_LEN - 4,
                ..LAYOUT
            },
            WRITE_SIZE,
            ConfigError::DfuUnaligned,
        ),
        (
            Layout {
                state_offset: 2,
                ..LAYOUT
            },
            WRITE_SIZE,
            ConfigError::StateUnaligned,
        ),
        (
            Layout {
                state_len: 100,
                ..LAYOUT
            },
            WRITE_SIZE,
            ConfigError::StateUnaligned,
        ),
        (
            Layout {
                state_offset: DFU_OFFSET + DFU_LEN - 0x1000,
                ..LAYOUT
            },
            WRITE_SIZE,
            ConfigError::PartitionsOverlap,
        ),
        (
            Layout {
                dfu_offset: 0,
                dfu_len: 0x1000,
                state_offset: 0,
                state_len: 0x1000,
            },
            WRITE_SIZE,
            ConfigError::PartitionsOverlap,
        ),
        // Aligned, but offset + length overflows u32.
        (
            Layout {
                dfu_offset: 0xFFFF_F000,
                dfu_len: 0x2000,
                ..LAYOUT
            },
            WRITE_SIZE,
            ConfigError::PartitionOutOfRange,
        ),
        (
            Layout {
                state_offset: 0xFFFF_F000,
                state_len: 0x2000,
                ..LAYOUT
            },
            WRITE_SIZE,
            ConfigError::PartitionOutOfRange,
        ),
    ];
    for (layout, aligned_len, expected) in cases {
        let mut aligned = vec![0u8; aligned_len];
        assert_eq!(
            keelsign_embassy::Updater::new(&shared, layout, &mut aligned, &lms_config()).err(),
            Some(Error::Config(expected)),
            "{layout:?}"
        );
    }
    let mut aligned = [0u8; WRITE_SIZE];
    assert_eq!(
        keelsign_embassy::Updater::new(
            &shared,
            LAYOUT,
            &mut aligned,
            &Config::new(Policy::PqOnly, bad_key, [])
        )
        .err(),
        Some(Error::KeySet(KeySetError::InvalidPublicKeyLength(
            Algorithm::LmsHss
        )))
    );
    // Adjacent partitions in either order are fine.
    for layout in [
        LAYOUT,
        Layout {
            dfu_offset: 0,
            dfu_len: DFU_LEN,
            state_offset: DFU_LEN,
            state_len: STATE_LEN,
        },
    ] {
        let mut aligned = [0u8; WRITE_SIZE];
        assert!(
            keelsign_embassy::Updater::new(&shared, layout, &mut aligned, &lms_config()).is_ok(),
            "{layout:?}"
        );
    }
    assert!(shared.into_inner().ops.is_empty(), "no flash access");
}

/// The state magic `magic` written over the whole first word of the state partition (as
/// the bootloader leaves it).
fn with_state(mut flash: Flash, magic: u8) -> Flash {
    let start = STATE_OFFSET as usize;
    flash.mem[start..start + WRITE_SIZE].fill(magic);
    flash
}

/// embassy-boot allows a new update from `Revert` (after a failed update) and `DfuDetach`,
/// as from `Boot`; both updaters mark a valid image there.
#[test]
fn marking_is_allowed_from_revert_and_dfu_detach() {
    const REVERT_MAGIC: u8 = 0xC0;
    const DFU_DETACH_MAGIC: u8 = 0xE0;
    for (magic, state) in [
        (REVERT_MAGIC, State::Revert),
        (DFU_DETACH_MAGIC, State::DfuDetach),
    ] {
        let start = with_state(flash_with(image(LMS_IMAGE)), magic);
        // The state reads as expected before marking.
        {
            let shared = Shared::new(RefCell::new(start.clone()));
            let mut aligned = [0u8; WRITE_SIZE];
            let mut updater = blocking_updater(&shared, &mut aligned, &lms_config()).unwrap();
            assert_eq!(updater.get_state().unwrap(), state);
        }
        for (result, flash) in [
            mark_blocking(start.clone(), &lms_config()),
            mark_async(start, &lms_config()),
        ] {
            result.unwrap_or_else(|e| panic!("from {state:?}: {e:?}"));
            assert_eq!(state_word(&flash), [SWAP_MAGIC; 4], "from {state:?}");
            assert!(mutations_only_in_state(&flash.ops), "from {state:?}");
        }
    }
}

/// A rejected image never reaches the caller's `accept` check, in either updater.
#[test]
fn accept_is_not_called_when_verify_rejects() {
    let mut tampered = flash_with(image(LMS_IMAGE));
    tampered.mem[DFU_OFFSET as usize + 0x200] ^= 0x01;
    let config = lms_config();
    let mut tlv_buf = [0u8; 4096];
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    let expected = Some(Error::Rejected(keelsign_verify::Error::Image(
        ImageError::DigestMismatch,
    )));

    let mut called = false;
    let shared = Shared::new(RefCell::new(tampered.clone()));
    {
        let mut aligned = [0u8; WRITE_SIZE];
        let mut updater = blocking_updater(&shared, &mut aligned, &config).unwrap();
        let result = updater.verify_and_mark_updated_if(&mut tlv_buf, &mut chunk, |_| {
            called = true;
            true
        });
        assert_eq!(result.err(), expected);
    }
    assert!(
        !called,
        "blocking: accept must not run for a rejected image"
    );
    let flash = shared.into_inner().into_inner();
    assert!(flash.ops.iter().all(|op| !op.mutates()));

    let shared = AsyncShared::new(tampered);
    {
        let mut aligned = [0u8; WRITE_SIZE];
        let mut updater = async_updater(&shared, &mut aligned, &config).unwrap();
        let result = embassy_futures::block_on(updater.verify_and_mark_updated_if(
            &mut tlv_buf,
            &mut chunk,
            |_| {
                called = true;
                true
            },
        ));
        assert_eq!(result.err(), expected);
    }
    assert!(!called, "async: accept must not run for a rejected image");
    assert!(shared.into_inner().ops.iter().all(|op| !op.mutates()));
}

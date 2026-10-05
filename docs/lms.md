# LMS/HSS: stateful keys (SHA-69)

An LMS/HSS signing key is not one key. It is a bundle of one-time keys, called
*leaves*, plus one public key that vouches for all of them. Every signature spends one
leaf. A key made with `keelsign keygen --alg lms-sha256-m32-h10` has 1,024 leaves, so it
can sign 1,024 images and then it is used up.

The one rule that matters: **a leaf must never sign twice.** If the same leaf signs two
different images, anyone who sees both signatures can forge signatures that devices
accept. keelsign keeps a record of the used leaves next to the key (the *state*), and
this page explains why that record must never go backwards and how to handle the key so
that it does not. The file formats and what `sign` does step by step are in
[keys.md, Stateful LMS keys](keys.md#stateful-lms-keys).

A solo developer who signs on one machine needs [Rules for handling a key](#rules-for-handling-a-key)
and can skip [What a production signing service needs](#what-a-production-signing-service-needs).
Words in *italics* are explained in the [Glossary](#glossary).

## Why a stateful key is dangerous

- **The failure is silent.** A signature made with a reused leaf verifies like any other.
  Nothing on the host or on the device warns you; the damage shows only when someone
  uses it.
- **Ordinary operations cause it.** Restoring the key from a backup, copying it to a
  second laptop, rolling a virtual machine back to a snapshot, or letting two CI runners
  sign with the same key all bring back leaves that were already used.
- **The damage is permanent.** Once a leaf has signed twice, the key cannot be trusted
  again. You must retire it: stop signing with it, put a new public key on every device
  and remove the old one. Devices in the field that still trust the old key stay at risk
  until they are updated.

ML-DSA and Ed25519 keys have no state and none of these problems. keelsign offers LMS/HSS
because its verifier is small and its security rests on hash functions alone.

## What a reused leaf leaks

A leaf (an LM-OTS one-time key, `LMOTS_SHA256_N32_W8`) works like 34 ladders, each
with 256 rungs. The private key is the bottom rung of every ladder; the public key is
the top. To sign, keelsign turns the image digest into 34 numbers and, for each ladder,
publishes the rung that number points to. Anyone can climb a ladder up from a published
rung (one hash per step) and check that they reach the top; nobody can climb down.

One signature therefore shows one rung per ladder, and that is safe: a forger would have
to climb down to sign anything else. The last two ladders are a *checksum* that goes up
when the others go down, so a forger cannot just pick a message whose numbers are all
higher.

Two signatures from the same leaf on different images show two rungs per ladder. The
lower of the two is now known, and from it an attacker can climb to any rung above. Any
message whose 34 numbers are at least those lower rungs on every ladder, checksum ladders
included, can now be signed. The attacker tries image variants until one fits; with two
signatures that takes work, and with three or four reuses of the same leaf almost any
image fits.

With two levels (HSS L=2, `--hss-levels 2`) a top-level leaf signs the public key of a
bottom tree, and the bottom tree's leaves sign images. keelsign derives bottom tree
number *i* deterministically from the key, so a crash and a retry make the same bottom
tree and the same top-level signature: no harm. A restored copy of the key that builds a
*different* bottom tree number *i* under the same top-level leaf is the same break one
level up: the top-level leaf has then signed two different messages.

## One tree, one L

An HSS public key is `u32str(L) || pub[0]`: the number of levels `L` followed by the top
tree's public key. Inside an L=2 signature, the level-0 part is an ordinary LMS signature
over the bottom tree's public key `pub[1]`. By construction that part is also a valid
L=1 signature over those same bytes under the key `u32str(1) || pub[0]`.

That L=1 key has a different key ID from the L=2 key `u32str(2) || pub[0]`, so a device
that trusts only the L=2 key is not affected. It becomes exploitable only if someone
provisions both forms of the same tree on a device: then every top-level signature the
signer ever published is also a valid L=1 image signature over attacker-visible bytes.

The rule: **never trust the same LMS tree at two different L values.** keelsign helps:
`keelsign keygen` fixes L when it creates a key (it is part of the public key, and every
signature checks it), and `keelsign verify --cnsa-2.0` accepts L=1 keys only. Do not
build a device key list by editing the first four bytes of a public key.

## Rules for handling a key

These rules apply to every LMS/HSS key keelsign creates. The never rules first:

- **Never sign with a copy.** Never copy the key to a second machine and sign on both,
  never sign from a restored backup, a virtual-machine snapshot or a cloned disk, and
  never let two CI runners or two people sign with the same key. Each of these reuses
  leaves.
- **Never run `keygen --force` over a key that a `sign` is using.** The running `sign`
  can then write the old key's state over the new key's state file, and the new key is
  refused with exit code 10 from then on.
- **Never edit or recreate `FILE.state` or `FILE.journal` by hand.** If the state is
  lost, the key is lost.

What to do:

- Keep `FILE`, `FILE.state` and `FILE.journal` together in one directory on a local disk
  of one machine, and sign only with keelsign. The journal is also a lock, but the lock
  only works on that one machine: another machine, or a network file system that does
  not honour `flock`, is not kept out.
- One signer per key: one machine, one person or pipeline at a time.
- What keelsign catches: a missing state file or journal (exit 10), a state file of
  another key (exit 10), and a state file restored on its own from a copy, because the
  journal then records a leaf the state file has not reached (exit 10, "restored from a
  copy"). What it cannot catch: the whole directory (key, state and journal together)
  copied or restored. That copy looks exactly like the original.
- Back up the **public key** freely. Back up the private key only if the backup can
  never be used to sign, for example an offline copy kept for audit that a written
  procedure forbids signing with. Do not back up the state file to restore it later.
- If the state is lost or you suspect a copy has signed, **retire the key**: generate a
  new one, put its public key on the devices next to the old one, switch signing to the
  new key, then remove the old key from the devices.
- `keygen` refuses to overwrite an existing key, state file or journal (exit 3).
  `--force` writes a new key with fresh state, and the old key's state is gone: use it
  only for a key that has never signed anything you shipped.
- Watch the `leaf: N of M (K left)` line `sign` prints and plan the next key well before
  the leaves run out; a used-up key fails with exit code 11 (`LeafIndexExhausted`).
- On a hybrid device (`Policy::Hybrid`), an image passes if it carries a valid signature
  from **any** trusted Ed25519 key and a valid signature from **any** trusted
  post-quantum key; the two halves are not bound to one signer
  ([SHA-319](https://linear.app/shakooky/issue/SHA-319) tracks binding them). Keep the
  device key lists short.

## What a production signing service needs

keelsign's state handling protects one signer on one machine. A service that signs for a
team, or from CI, needs more. This section is a starting point for that service; a solo
developer can skip it.

- **Reserve, then sign.** Keep the leaf counter in a strongly consistent store (a
  database transaction at the serialisable level, or a compare-and-swap on one record).
  A signer reserves a leaf, and the reservation is durable before any hash of the
  signature is computed. The counter only ever goes up; a failed or abandoned
  reservation wastes the leaf and is never handed out again.
- **Keys in hardware.** NIST SP 800-208, section 8.1 (Key Generation and Signature
  Generation), allows LMS/HSS key generation and signing only inside hardware
  cryptographic modules validated to FIPS 140-2 or FIPS 140-3 Level 3 or higher, so
  that the private seed and the leaf counter never leave the module. keelsign's
  file-based keys are for development and for teams that accept that gap knowingly.
- **Hand out subtrees, not copies.** With HSS (SP 800-208, section 7.1) the top tree,
  kept offline or in a hardware module, signs the public keys of bottom trees. Give each
  signer its own bottom tree (or a range of leaves no other signer uses), so that no two
  signers can ever reach the same leaf. Track how many leaves each subtree has left and
  rotate each one before it runs out.
- **Audit and alert.** Log every reservation and every signature with the leaf it used.
  Alert on a rejected or duplicated reservation, on a counter that goes down and on a
  key nearing exhaustion.
- **What keelsign has today:** the journal lock, the state bound to the key ID, the
  detection of a state file restored on its own, and a crash-safe order (state written
  and reservation recorded before signing). **What it does not have:** a high-water mark
  kept outside the key's directory, so that a restored directory would be caught
  ([SHA-308](https://linear.app/shakooky/issue/SHA-308)).

## Glossary

- **Leaf**: one one-time key inside an LMS tree. Each signature uses one leaf.
- **One-time signature (OTS)**: a signature scheme whose key may sign only one message.
  LM-OTS is the one LMS uses.
- **Tree**: an LMS key, a Merkle tree whose leaves are one-time keys and whose root is
  the public key.
- **Level (L)**: the number of trees stacked in an HSS key. With L=1 the tree signs
  images; with L=2 a top tree signs bottom trees, which sign images.
- **Checksum**: extra values in a one-time signature that grow when the others shrink,
  so a forger cannot simply move every value up.
- **State file** (`FILE.state`): where keelsign records the next unused leaf.
- **Journal** (`FILE.journal`): an append-only record of every leaf keelsign reserved;
  also the key's lock.
- **HSM** (hardware security module): a tamper-resistant device that holds keys and
  signs without ever releasing the private key.
- **Strongly consistent**: a store in which every reader sees the latest completed
  write, so two signers can never reserve the same leaf.

## Plain-language review

This page must be readable by a non-cryptographer (SHA-69 TP3). A firmware or software
engineer who has not read RFC 8554 reads it once (30 minutes at most) and then answers,
without re-reading:

1. In one sentence, what goes wrong if the same leaf signs twice? (Expected: anyone can
   forge signatures; the key must be retired.)
2. Name the three files and say which one must never be restored from a backup and why.
3. What does `--force` do, and when is it unsafe?
4. Two laptops, one key, one signs today and the other tomorrow: allowed? Why not?
5. In your own words: why must a device never trust the same tree as both a 1-level and
   a 2-level key?
6. Which sentences needed a second read? (Each one is a fix.)
7. Which terms were used before they were explained? (Expected: none; the glossary
   covers the rest.)
8. Could you find the "never" rules within 30 seconds? (Expected: yes, one bulleted
   section.)
9. Was it clear which parts a solo developer can skip and which are for a signing
   service?

Pass: questions 1 to 5 answered correctly, 7 empty, 8 yes; every item from 6 fixed or
consciously kept.

Reviewed by: (pending) on (date); changes: (pending).

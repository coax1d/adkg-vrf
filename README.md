# adkg-vrf

Threshold Verifiable Unpredictable Function (VUF) on BLS12-381, from an
aggregatable distributed key generation (DKG) protocol.

The scheme produces an unpredictable output by aggregating a threshold number
of *vanilla* BLS signatures on the input. It comprises two parts:

1. a **Distributed Key Generation (DKG)** protocol that produces some data for
   a set of BLS signers, and
2. a **BLS signature aggregation** scheme that leverages the data produced by
   the DKG to aggregate signatures from a subset of the signers into a
   threshold signature, and additionally produce a VUF output.

An interesting property of the scheme is that the signers are not required to
participate in the protocol in any way other than producing vanilla BLS
signatures. That allows transforming any deployed BLS signature scheme, where
the same message is being signed by multiple signers, into a threshold scheme
or a randomness beacon.

The implementation follows the notes by Alistair Stewart:

1. https://hackmd.io/3968Gr5hSSmef-nptg2GRw
2. https://hackmd.io/xqYBrigYQwyKM_0Sn5Xf4w

## Layout

| Module | What |
|---|---|
| `dkg` | The DKG protocol: dealing, transcript aggregation, verification, finalization |
| `pvss` | Aggregatable publicly verifiable secret sharing, used by `dkg` |
| `bls` | Vanilla BLS signers and the threshold wrapper (aggregate sig → VUF output) |
| `agg` | Aggregation of augmented BLS signatures (sig + signer pk + bgpk) |
| `koe` | Knowledge-of-exponent argument |
| `straus` | Straus multi-scalar multiplication used in verification |
| `old_dkg` | Previous iteration of the DKG, kept for reference |

## Usage

```rust
use adkg_vrf::bls::{threshold::ThresholdVk, vanilla::BlsSigner};
use adkg_vrf::dkg::{transcript::Transcript, Dkg};
use ark_bls12_381::Bls12_381;
use ark_std::test_rng;

let rng = &mut test_rng();

// n BLS signers, threshold t of them suffice to produce an output.
let (n, t) = (7, 5);
let signers: Vec<BlsSigner<Bls12_381>> = (0..n).map(|_| BlsSigner::new(rng)).collect();
let signers_pks: Vec<_> = signers.iter().map(|s| s.bls_pk_g2).collect();

// Dealers run the DKG on behalf of the signers (the signers do nothing).
let dealers: Vec<_> = (0..3).map(|_| BlsSigner::<Bls12_381>::new(rng)).collect();
let dealer_pks: Vec<_> = dealers.iter().map(|d| d.bls_pk_g1).collect();

let dkg = Dkg::<Bls12_381>::new(signers_pks, t, dealer_pks.clone(), dealer_pks.len())?;

// Each dealer deals and signs a transcript; transcripts are publicly
// verifiable and aggregatable.
let transcripts: Vec<Transcript<Bls12_381>> = dealers
    .into_iter()
    .map(|dealer| dkg.deal_and_sign(rng, (dealer.sk, dealer.bls_pk_g1)).unwrap())
    .collect();

dkg.verify(&transcripts[0], rng)?;
let agg_transcript = Dkg::<Bls12_381>::aggregate(transcripts);
dkg.verify(&agg_transcript, rng)?;

// Finalization yields the per-signer data needed to aggregate signatures
// into a threshold signature / VUF output.
let keys = dkg.finalize(agg_transcript, rng)?;
let threshold_vk = ThresholdVk::from_share(&keys.secret_sharing);
```

A full aggregation example (signature aggregator session, Lagrange
interpolation over the participating signers, VUF evaluation) is in the
`it_works` test in `src/lib.rs`.

## no_std

The crate is `no_std`-compatible: build with `--no-default-features`.

## Status

**Not audited, not for production use.** Research code. Known gaps are tracked
as `TODO`s in `src/lib.rs` (Fiat-Shamir hardening, subgroup checks, error
handling, among others).

## License

Apache License 2.0.

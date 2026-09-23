#![cfg_attr(not(feature = "std"), no_std)]

use crate::dkg::aggregator::TranscriptAggregator;
use crate::pvss::SecretSharing;
use ark_ec::pairing::Pairing;
pub use dkg::transcript;
pub use error::Error;

pub mod agg;
pub mod bls;
pub mod dkg;
mod error;
pub mod koe;
/// Threshold Verifiable Unpredictable Function (VUF) scheme.
/// Produces an unpredictable output by aggregating a threshold number of vanilla BLS signatures on the input.
///
/// The scheme comprises 2 parts:
/// 1. a Distributed Key Generation (DKG) protocol that produces some data for a set of BLS signers, and
/// 2. a BLS signature aggregation scheme that leverages the data produced by the DKG
///    to aggregate the signatures from a subset of the signers into a threshold signature,
///    and additionally produce a VUF output.
///
/// An interesting property of the scheme is that the signers are not required to participate
/// in the protocol in any way other than producing vanilla BLS signatures.
/// That allows to transform any deployed BLS signature scheme, where the same message is being signed by multiple signers,
/// into a threshold scheme or a randomness beacon.
///
/// The implementation follows the notes by Alistair Stewart:
/// 1. https://hackmd.io/3968Gr5hSSmef-nptg2GRw
/// 2. https://hackmd.io/xqYBrigYQwyKM_0Sn5Xf4w
/// TODO: is there a paper?

/// Aggregatable Publicly Verifiable Secret Sharing Scheme
mod old_dkg;
pub mod pvss;
pub mod straus;
pub mod utils;

pub struct ThresholdCrypto<C: Pairing> {
    secret_sharing: SecretSharing<C>,
    params: pvss::Params<C>,
}

impl<C: Pairing> ThresholdCrypto<C> {
    fn config(&self) -> pvss::Config<C> {
        self.params.config.clone()
    }
}

pub type BlsDkg = dkg::Dkg<ark_bls12_381::Bls12_381>;
pub type BlsSignerPk = ark_bls12_381::G2Affine;
pub type BlsTranscriptAggregator = TranscriptAggregator<ark_bls12_381::Bls12_381>;
pub type DkgTranscript = transcript::Transcript<ark_bls12_381::Bls12_381>;

// must have
// TODO: Fiat-Shamir
// TODO: cofactors/subgroup checks
// TODO: ark-substrate

// nice to have
// TODO: CP proofs
// TODO: integration test
// TODO: half-aggregation
// TODO: bench for logn = 16, 20

// nice to consider
// TODO: IBE
// TODO: resharing?
// TODO: backsharing
// TODO: multiple Cs?

// TODO: test single signer, t = 1
// TODO: test t = n
// TODO: test multiple dealings

#[cfg(test)]
mod tests {
    use crate::bls::threshold::{AggThresholdSig, ThresholdVk};
    use crate::bls::vanilla::{BlsSigner, StandaloneSig};
    use crate::dkg::transcript::Transcript;
    use crate::dkg::Dkg;
    use crate::utils::BarycentricDomain;
    use crate::{pvss, Error};
    use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Projective};
    use ark_ec::pairing::Pairing;
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
    use ark_ff::Zero;
    use ark_poly::EvaluationDomain;
    use ark_std::test_rng;
    use ark_std::vec::Vec;
    use hashbrown::HashMap;

    pub fn aggregator<C: Pairing>(
        signer_pks: &[C::G2Affine],
        bgpks: Vec<C::G2Affine>,
    ) -> crate::agg::SignatureAggregator<C> {
        let pks: HashMap<_, _> = signer_pks
            .iter()
            .cloned()
            .zip(bgpks)
            .enumerate()
            .map(|(j, (signer_pk_j, bgpk_j))| (signer_pk_j, (bgpk_j, j)))
            .collect();
        crate::agg::SignatureAggregator {
            g2: C::G2Affine::generator(),
            pks,
        }
    }

    pub fn aggregate_augmented_sigs<C: Pairing>(
        augmented_sigs: Vec<Option<AggThresholdSig<C>>>,
        config: &pvss::Config<C>,
    ) -> AggThresholdSig<C> {
        assert_eq!(augmented_sigs.len(), config.n);
        let mut bitmask: Vec<bool> = augmented_sigs.iter().map(|o| o.is_some()).collect();
        bitmask.resize(config.domain.size(), false);
        let set_bits_count = bitmask.iter().filter(|b| **b).count();
        assert!(set_bits_count >= config.t);
        let lis = BarycentricDomain::from_subset(config.domain, &bitmask)
            .lagrange_basis_at(C::ScalarField::zero());
        let augmented_sigs: Vec<AggThresholdSig<C>> =
            augmented_sigs.into_iter().flatten().collect();
        let bls_sigs: Vec<_> = augmented_sigs
            .iter()
            .map(|s| s.bls_sig_with_pk.sig)
            .collect();
        let bls_pks: Vec<_> = augmented_sigs
            .iter()
            .map(|s| s.bls_sig_with_pk.pk)
            .collect();
        let bgpks: Vec<_> = augmented_sigs.iter().map(|s| s.bgpk).collect();
        let asig = C::G1::msm(&bls_sigs, &lis).unwrap().into_affine();
        let apk = C::G2::msm(&bls_pks, &lis).unwrap().into_affine();
        let abgpk = C::G2::msm(&bgpks, &lis).unwrap().into_affine();
        AggThresholdSig {
            bls_sig_with_pk: StandaloneSig { sig: asig, pk: apk },
            bgpk: abgpk,
        }
    }

    /// Runs the full DKG -> threshold-sign -> VUF pipeline for `n` signers with threshold `t`,
    /// with `num_dealers` of `t_dkg` required dealers actually dealing.
    /// Returns the VUF output evaluated by all `n` signers.
    fn run_e2e(n: usize, t: usize, num_dealer_keys: usize, num_dealers: usize) {
        let rng = &mut test_rng();

        let signers: Vec<BlsSigner<Bls12_381>> = (0..n).map(|_| BlsSigner::new(rng)).collect();
        let signers_pks: Vec<_> = signers.iter().map(|s| s.bls_pk_g2).collect();

        let dealers: Vec<_> = (0..num_dealer_keys)
            .map(|_| BlsSigner::<Bls12_381>::new(rng))
            .collect();
        let dealer_pks: Vec<G1Affine> = dealers.iter().map(|d| d.bls_pk_g1).collect();

        let dkg =
            Dkg::<Bls12_381>::new(signers_pks.clone(), t, dealer_pks.clone(), num_dealers).unwrap();

        let transcripts: Vec<Transcript<Bls12_381>> = dealers
            .into_iter()
            .take(num_dealers)
            .map(|dealer| {
                dkg.deal_and_sign(rng, (dealer.sk, dealer.bls_pk_g1))
                    .unwrap()
            })
            .collect();

        assert!(dkg.verify(&transcripts[0], rng).is_ok());

        let agg_transcript = Dkg::<Bls12_381>::aggregate(transcripts);

        assert!(dkg.verify(&agg_transcript, rng).is_ok());

        let keys = dkg.finalize(agg_transcript, rng).unwrap();

        let config = keys.config();
        let threshold_vk = ThresholdVk::from_share(&keys.secret_sharing);
        let sig_aggregator = aggregator::<Bls12_381>(&signers_pks, keys.secret_sharing.bgpk);

        let message = G1Projective::generator();
        let sigs: Vec<_> = signers.iter().map(|s| s.sign_g1(message)).collect();

        let mut sig_agg_session_n = sig_aggregator.start_session(message.into_affine());
        sig_agg_session_n.append_verify_sigs(sigs.clone()).unwrap();
        let augmented_sigs_n = sig_agg_session_n.finalize();
        let threshold_sig_n = aggregate_augmented_sigs(augmented_sigs_n, &config);
        let vuf_n = threshold_vk
            .vuf_unoptimized(&threshold_sig_n, message)
            .expect("valid threshold signature");

        let mut sig_agg_session_t = sig_aggregator.start_session(message.into_affine());
        sig_agg_session_t
            .append_verify_sigs(sigs.into_iter().take(t).collect())
            .unwrap();
        let augmented_sigs_t = sig_agg_session_t.finalize();
        let threshold_sig_t = aggregate_augmented_sigs(augmented_sigs_t, &config);
        let vuf_t = threshold_vk
            .vuf_unoptimized(&threshold_sig_t, message)
            .expect("valid threshold signature");
        assert_eq!(vuf_t, vuf_n);
    }

    #[test]
    fn it_works() {
        run_e2e(7, 5, 3, 3);
    }

    #[test]
    fn t_equals_1() {
        run_e2e(5, 1, 2, 1);
    }

    #[test]
    fn t_equals_n() {
        run_e2e(4, 4, 2, 2);
    }

    #[test]
    fn single_signer() {
        run_e2e(1, 1, 1, 1);
    }

    #[test]
    fn not_all_dealers_participate() {
        // 4 authorized dealer keys, any 2 suffice, only 3 deal.
        run_e2e(7, 5, 4, 3);
    }

    #[test]
    fn invalid_configs_rejected() {
        assert_eq!(
            pvss::Config::<Bls12_381>::new(0, 0),
            Err(Error::InvalidConfig)
        );
        assert_eq!(
            pvss::Config::<Bls12_381>::new(5, 0),
            Err(Error::InvalidConfig)
        );
        assert_eq!(
            pvss::Config::<Bls12_381>::new(5, 6),
            Err(Error::InvalidConfig)
        );
    }

    #[test]
    fn tampered_transcript_rejected() {
        let rng = &mut test_rng();

        let (n, t) = (7, 5);
        let signers_pks: Vec<_> = (0..n)
            .map(|_| BlsSigner::<Bls12_381>::new(rng).bls_pk_g2)
            .collect();
        let dealer = BlsSigner::<Bls12_381>::new(rng);
        let dkg = Dkg::<Bls12_381>::new(signers_pks, t, vec![dealer.bls_pk_g1], 1).unwrap();
        let mut transcript = dkg.deal_and_sign(rng, dealer.pk_in_g1()).unwrap();
        assert!(dkg.verify(&transcript, rng).is_ok());

        // Tamper with an encrypted share.
        transcript.agg_ss.payload.bgpk[0] =
            (transcript.agg_ss.payload.bgpk[0] + G2Projective::generator()).into_affine();
        assert_eq!(dkg.verify(&transcript, rng), Err(Error::InvalidSharing));
    }

    #[test]
    fn not_enough_contributions_rejected() {
        let rng = &mut test_rng();

        let (n, t) = (7, 5);
        let signers_pks: Vec<_> = (0..n)
            .map(|_| BlsSigner::<Bls12_381>::new(rng).bls_pk_g2)
            .collect();
        let dealers: Vec<_> = (0..2).map(|_| BlsSigner::<Bls12_381>::new(rng)).collect();
        let dealer_pks: Vec<G1Affine> = dealers.iter().map(|d| d.bls_pk_g1).collect();
        // Require 2 dealers, only 1 deals.
        let dkg = Dkg::<Bls12_381>::new(signers_pks, t, dealer_pks, 2).unwrap();
        let transcript = dkg.deal_and_sign(rng, dealers[0].pk_in_g1()).unwrap();
        assert!(matches!(
            dkg.finalize(transcript, rng),
            Err(Error::NotEnoughContributions)
        ));
    }
}

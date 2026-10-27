use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Zero;
use ark_poly::EvaluationDomain;
use ark_std::{vec, vec::Vec};
use hashbrown::HashMap;

use crate::bls::threshold::AggThresholdSig;
use crate::bls::vanilla::StandaloneSig;
use crate::pvss;
use crate::utils::BarycentricDomain;
use crate::Error;

pub struct SignatureAggregator<C: Pairing> {
    // to verify BLS sigs with the keys in G2
    pub(crate) g2: C::G2Affine,
    // map bls_pk_j -> (bgpk_j, j)
    pub(crate) pks: HashMap<C::G2Affine, (C::G2Affine, usize)>,
}

impl<C: Pairing> SignatureAggregator<C> {
    /// An aggregator for the signers of a DKG output: `signer_pks` are the signers' BLS keys in
    /// the order they were dealt to, and `bgpks` the matching entries of the secret sharing's
    /// `bgpk` (one per signer, in the same order).
    pub fn new(signer_pks: &[C::G2Affine], bgpks: &[C::G2Affine]) -> Result<Self, Error> {
        if signer_pks.len() != bgpks.len() {
            return Err(Error::InvalidConfig);
        }
        let pks: HashMap<_, _> = signer_pks
            .iter()
            .cloned()
            .zip(bgpks.iter().cloned())
            .enumerate()
            .map(|(j, (signer_pk_j, bgpk_j))| (signer_pk_j, (bgpk_j, j)))
            .collect();
        if pks.len() != signer_pks.len() {
            // A duplicate signer key.
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            g2: C::G2Affine::generator(),
            pks,
        })
    }

    pub fn start_session(&self, message: C::G1Affine) -> Session<C> {
        Session {
            g2: self.g2,
            message,
            pks: &self.pks,
            augmented_sigs: vec![None; self.pks.len()],
        }
    }
}

/// Aggregates the augmented signatures of a [`Session`] (indexed by signer, as returned by
/// [`Session::finalize`]) into a threshold signature: the signatures, the signers' keys and their
/// `bgpk`s are Lagrange-interpolated at `0` over the signers' evaluation domain.
///
/// Needs at least `config.t` signatures; any `t` of them give the same VUF output.
pub fn aggregate<C: Pairing>(
    augmented_sigs: Vec<Option<AggThresholdSig<C>>>,
    config: &pvss::Config<C>,
) -> Result<AggThresholdSig<C>, Error> {
    if augmented_sigs.len() != config.n {
        return Err(Error::InvalidConfig);
    }
    let mut bitmask: Vec<bool> = augmented_sigs.iter().map(|o| o.is_some()).collect();
    if bitmask.iter().filter(|b| **b).count() < config.t {
        return Err(Error::NotEnoughSignatures);
    }
    bitmask.resize(config.domain.size(), false);
    let lis = BarycentricDomain::from_subset(config.domain, &bitmask)
        .lagrange_basis_at(C::ScalarField::zero());
    let augmented_sigs: Vec<AggThresholdSig<C>> = augmented_sigs.into_iter().flatten().collect();
    let bls_sigs: Vec<_> = augmented_sigs
        .iter()
        .map(|s| s.bls_sig_with_pk.sig)
        .collect();
    let bls_pks: Vec<_> = augmented_sigs
        .iter()
        .map(|s| s.bls_sig_with_pk.pk)
        .collect();
    let bgpks: Vec<_> = augmented_sigs.iter().map(|s| s.bgpk).collect();
    let asig = C::G1::msm(&bls_sigs, &lis).map_err(|_| Error::MsmFailed)?;
    let apk = C::G2::msm(&bls_pks, &lis).map_err(|_| Error::MsmFailed)?;
    let abgpk = C::G2::msm(&bgpks, &lis).map_err(|_| Error::MsmFailed)?;
    Ok(AggThresholdSig {
        bls_sig_with_pk: StandaloneSig {
            sig: asig.into_affine(),
            pk: apk.into_affine(),
        },
        bgpk: abgpk.into_affine(),
    })
}

pub struct Session<'a, C: Pairing> {
    // to verify BLS sigs with the keys in G2
    g2: C::G2Affine,
    // the message on that signatures are being aggregated
    message: C::G1Affine,
    // map bls_pk_j -> (bgpk_j, j)
    pks: &'a HashMap<C::G2Affine, (C::G2Affine, usize)>,
    /// `Vec` of length `n` accumulating the augmented signatures stored at the right index.
    augmented_sigs: Vec<Option<AggThresholdSig<C>>>,
}

impl<'a, C: Pairing> Session<'a, C> {
    pub fn finalize(self) -> Vec<Option<AggThresholdSig<C>>> {
        self.augmented_sigs
    }

    /// Signatures MUST be
    /// 1. valid on the message
    /// 2. from a known pk
    /// duplicates allowed
    pub fn append_verify_sig(&mut self, sig: StandaloneSig<C>) -> Result<(), Error> {
        let (bgpk, j) = self.pks.get(&sig.pk).ok_or(Error::UnknownSigner)?.clone();
        if self.augmented_sigs[j].is_some() {
            return Err(Error::DuplicateSignature);
        }
        if !sig.verify_unoptimized(self.message.into(), self.g2) {
            return Err(Error::InvalidSignature);
        }
        self.augmented_sigs[j] = Some(AggThresholdSig {
            bls_sig_with_pk: sig,
            bgpk,
        });
        Ok(())
    }

    pub fn append_verify_sigs(&mut self, sigs: Vec<StandaloneSig<C>>) -> Result<(), Error> {
        sigs.into_iter().try_for_each(|s| self.append_verify_sig(s))
    }
}

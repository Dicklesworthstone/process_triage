//! Prior override system for signature-based prior customization.
//!
//! This module implements a hierarchical prior override system that allows
//! process-specific priors to be applied based on signature matches.
//!
//! ## Hierarchy (highest to lowest priority)
//! 1. **User** - Explicit user-defined overrides in policy
//! 2. **Signature** - Process-specific priors from signature database
//! 3. **Category** - Supervisor category-level defaults (future)
//! 4. **Global** - Default priors from config

use crate::config::priors::Priors;
use crate::supervision::signature::{BetaParams, MatchLevel, SignatureMatch, SignaturePriors};
use serde::Serialize;

/// Source of a prior value in the override hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorSource {
    /// Default global priors from configuration.
    Global,
    /// Category-level priors (e.g., all CI processes).
    Category,
    /// Signature-specific priors from the signature database.
    Signature,
    /// User-defined overrides from policy configuration.
    User,
}

impl PriorSource {
    /// Returns the priority of this source (higher = takes precedence).
    pub fn priority(&self) -> u8 {
        match self {
            PriorSource::Global => 0,
            PriorSource::Category => 1,
            PriorSource::Signature => 2,
            PriorSource::User => 3,
        }
    }
}

impl std::fmt::Display for PriorSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PriorSource::Global => write!(f, "global"),
            PriorSource::Category => write!(f, "category"),
            PriorSource::Signature => write!(f, "signature"),
            PriorSource::User => write!(f, "user"),
        }
    }
}

/// Tracking information for prior overrides.
#[derive(Debug, Clone, Serialize)]
pub struct PriorSourceInfo {
    /// The source that determined the priors.
    pub source: PriorSource,
    /// Signature name if source is Signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_name: Option<String>,
    /// Match level if a signature matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_level: Option<String>,
    /// Match score (0.0-1.0) if a signature matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_score: Option<f64>,
    /// Category name if source is Category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Details of which priors were actually overridden.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_overrides: Option<AppliedOverrides>,
}

impl Default for PriorSourceInfo {
    fn default() -> Self {
        Self {
            source: PriorSource::Global,
            signature_name: None,
            match_level: None,
            match_score: None,
            category: None,
            applied_overrides: None,
        }
    }
}

/// Record of which prior values were actually overridden.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AppliedOverrides {
    /// Override for useful class prior.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub useful: Option<OverriddenPrior>,
    /// Override for useful_bad class prior.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub useful_bad: Option<OverriddenPrior>,
    /// Override for abandoned class prior.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abandoned: Option<OverriddenPrior>,
    /// Override for zombie class prior.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zombie: Option<OverriddenPrior>,
}

impl AppliedOverrides {
    /// Returns true if any overrides were applied.
    pub fn has_any(&self) -> bool {
        self.useful.is_some()
            || self.useful_bad.is_some()
            || self.abandoned.is_some()
            || self.zombie.is_some()
    }
}

/// Details of a single prior override.
#[derive(Debug, Clone, Serialize)]
pub struct OverriddenPrior {
    /// Original prior_prob value before override.
    pub original_prob: f64,
    /// New prior_prob value after override.
    pub new_prob: f64,
    /// Beta distribution alpha parameter (if from signature).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpha: Option<f64>,
    /// Beta distribution beta parameter (if from signature).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beta: Option<f64>,
}

impl OverriddenPrior {
    /// Create from BetaParams and original probability.
    pub fn from_beta_params(params: &BetaParams, original_prob: f64) -> Self {
        Self {
            original_prob,
            new_prob: params.mean(),
            alpha: Some(params.alpha),
            beta: Some(params.beta),
        }
    }

    /// Create from a direct probability override.
    pub fn from_prob(original_prob: f64, new_prob: f64) -> Self {
        Self {
            original_prob,
            new_prob,
            alpha: None,
            beta: None,
        }
    }
}

/// Context for resolving priors with override hierarchy.
pub struct PriorContext<'a> {
    /// Global priors from configuration.
    pub global_priors: &'a Priors,
    /// Optional signature match for this process.
    pub signature_match: Option<&'a SignatureMatch<'a>>,
    /// Optional user-defined overrides.
    pub user_overrides: Option<&'a UserPriorOverrides>,
}

/// User-defined prior overrides from policy configuration.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UserPriorOverrides {
    /// Override for useful class prior probability.
    pub useful: Option<f64>,
    /// Override for useful_bad class prior probability.
    pub useful_bad: Option<f64>,
    /// Override for abandoned class prior probability.
    pub abandoned: Option<f64>,
    /// Override for zombie class prior probability.
    pub zombie: Option<f64>,
}

impl UserPriorOverrides {
    /// Returns true if any overrides are set.
    pub fn has_any(&self) -> bool {
        self.useful.is_some()
            || self.useful_bad.is_some()
            || self.abandoned.is_some()
            || self.zombie.is_some()
    }
}

/// Result of prior resolution with source tracking.
#[derive(Debug, Clone)]
pub struct ResolvedPriors {
    /// The resolved priors to use.
    pub priors: Priors,
    /// Information about where the priors came from.
    pub source_info: PriorSourceInfo,
}

/// Apply signature priors to a Priors config, returning overrides info.
fn apply_signature_priors(
    priors: &mut Priors,
    sig_priors: &SignaturePriors,
) -> AppliedOverrides {
    let mut overrides = AppliedOverrides::default();

    if let Some(ref useful_beta) = sig_priors.useful {
        let original = priors.classes.useful.prior_prob;
        priors.classes.useful.prior_prob = useful_beta.mean();
        overrides.useful = Some(OverriddenPrior::from_beta_params(useful_beta, original));
    }

    if let Some(ref useful_bad_beta) = sig_priors.useful_bad {
        let original = priors.classes.useful_bad.prior_prob;
        priors.classes.useful_bad.prior_prob = useful_bad_beta.mean();
        overrides.useful_bad = Some(OverriddenPrior::from_beta_params(useful_bad_beta, original));
    }

    if let Some(ref abandoned_beta) = sig_priors.abandoned {
        let original = priors.classes.abandoned.prior_prob;
        priors.classes.abandoned.prior_prob = abandoned_beta.mean();
        overrides.abandoned = Some(OverriddenPrior::from_beta_params(abandoned_beta, original));
    }

    if let Some(ref zombie_beta) = sig_priors.zombie {
        let original = priors.classes.zombie.prior_prob;
        priors.classes.zombie.prior_prob = zombie_beta.mean();
        overrides.zombie = Some(OverriddenPrior::from_beta_params(zombie_beta, original));
    }

    overrides
}

/// Apply user overrides to a Priors config, returning overrides info.
fn apply_user_overrides(priors: &mut Priors, user: &UserPriorOverrides) -> AppliedOverrides {
    let mut overrides = AppliedOverrides::default();

    if let Some(prob) = user.useful {
        let original = priors.classes.useful.prior_prob;
        priors.classes.useful.prior_prob = prob;
        overrides.useful = Some(OverriddenPrior::from_prob(original, prob));
    }

    if let Some(prob) = user.useful_bad {
        let original = priors.classes.useful_bad.prior_prob;
        priors.classes.useful_bad.prior_prob = prob;
        overrides.useful_bad = Some(OverriddenPrior::from_prob(original, prob));
    }

    if let Some(prob) = user.abandoned {
        let original = priors.classes.abandoned.prior_prob;
        priors.classes.abandoned.prior_prob = prob;
        overrides.abandoned = Some(OverriddenPrior::from_prob(original, prob));
    }

    if let Some(prob) = user.zombie {
        let original = priors.classes.zombie.prior_prob;
        priors.classes.zombie.prior_prob = prob;
        overrides.zombie = Some(OverriddenPrior::from_prob(original, prob));
    }

    overrides
}

/// Format MatchLevel as a string for serialization.
fn match_level_to_string(level: &MatchLevel) -> String {
    match level {
        MatchLevel::None => "none".to_string(),
        MatchLevel::GenericCategory => "generic_category".to_string(),
        MatchLevel::CommandOnly => "command_only".to_string(),
        MatchLevel::CommandPlusArgs => "command_plus_args".to_string(),
        MatchLevel::ExactCommand => "exact_command".to_string(),
        MatchLevel::MultiPattern => "multi_pattern".to_string(),
    }
}

/// Resolve priors using the override hierarchy.
///
/// Priority order (highest to lowest):
/// 1. User overrides
/// 2. Signature-specific priors
/// 3. Category defaults (TODO: not yet implemented)
/// 4. Global priors
pub fn resolve_priors(context: &PriorContext<'_>) -> ResolvedPriors {
    // Start with a clone of global priors
    let mut priors = context.global_priors.clone();
    let mut source_info = PriorSourceInfo::default();

    // Apply signature priors if available
    if let Some(sig_match) = context.signature_match {
        if let Some(ref sig_priors) = sig_match.signature.priors {
            let overrides = apply_signature_priors(&mut priors, sig_priors);

            if overrides.has_any() {
                source_info = PriorSourceInfo {
                    source: PriorSource::Signature,
                    signature_name: Some(sig_match.signature.name.clone()),
                    match_level: Some(match_level_to_string(&sig_match.level)),
                    match_score: Some(sig_match.score),
                    category: sig_match
                        .signature
                        .category
                        .as_ref()
                        .map(|c| format!("{:?}", c)),
                    applied_overrides: Some(overrides),
                };
            }
        }
    }

    // Apply user overrides (highest priority)
    if let Some(user) = context.user_overrides {
        if user.has_any() {
            let overrides = apply_user_overrides(&mut priors, user);
            source_info = PriorSourceInfo {
                source: PriorSource::User,
                signature_name: None,
                match_level: None,
                match_score: None,
                category: None,
                applied_overrides: Some(overrides),
            };
        }
    }

    ResolvedPriors { priors, source_info }
}

/// Compute posterior with prior override resolution.
///
/// This is a convenience function that resolves priors from the context
/// and then computes the posterior, returning both the result and the
/// prior source information for tracking.
pub fn compute_posterior_with_overrides(
    context: &PriorContext<'_>,
    evidence: &super::Evidence,
) -> Result<(super::PosteriorResult, PriorSourceInfo), super::PosteriorError> {
    let resolved = resolve_priors(context);
    let result = super::compute_posterior(evidence, &resolved.priors)?;
    Ok((result, resolved.source_info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::priors::Priors;
    use crate::supervision::signature::{MatchDetails, SupervisorSignature};
    use crate::supervision::SupervisorCategory;

    fn default_priors() -> Priors {
        Priors::default()
    }

    #[test]
    fn test_global_priors_default() {
        let global = default_priors();
        let context = PriorContext {
            global_priors: &global,
            signature_match: None,
            user_overrides: None,
        };

        let resolved = resolve_priors(&context);
        assert_eq!(resolved.source_info.source, PriorSource::Global);
        assert!(resolved.source_info.signature_name.is_none());
        assert!(resolved.source_info.applied_overrides.is_none());
    }

    #[test]
    fn test_signature_priors_override() {
        let global = default_priors();
        let original_useful = global.classes.useful.prior_prob;
        let original_zombie = global.classes.zombie.prior_prob;

        let signature = SupervisorSignature {
            name: "test-process".to_string(),
            category: Some(SupervisorCategory::Ci),
            confidence_weight: 0.9,
            notes: None,
            patterns: Default::default(),
            expected_lifetime: None,
            expected_cpu: None,
            priors: Some(SignaturePriors {
                useful: Some(BetaParams::new(10.0, 1.0)), // mean ~0.91
                useful_bad: None,
                abandoned: None,
                zombie: Some(BetaParams::new(1.0, 10.0)), // mean ~0.09
            }),
        };

        let details = MatchDetails::default();
        let sig_match = SignatureMatch::new(&signature, MatchLevel::CommandOnly, details);

        let context = PriorContext {
            global_priors: &global,
            signature_match: Some(&sig_match),
            user_overrides: None,
        };

        let resolved = resolve_priors(&context);
        assert_eq!(resolved.source_info.source, PriorSource::Signature);
        assert_eq!(
            resolved.source_info.signature_name,
            Some("test-process".to_string())
        );

        // Check that overrides were recorded
        let overrides = resolved.source_info.applied_overrides.unwrap();
        assert!(overrides.useful.is_some());
        assert!(overrides.useful_bad.is_none());
        assert!(overrides.abandoned.is_none());
        assert!(overrides.zombie.is_some());

        // Check actual values changed
        let useful_override = overrides.useful.unwrap();
        assert!((useful_override.original_prob - original_useful).abs() < 0.001);
        assert!((useful_override.new_prob - 10.0 / 11.0).abs() < 0.001);

        let zombie_override = overrides.zombie.unwrap();
        assert!((zombie_override.original_prob - original_zombie).abs() < 0.001);
        assert!((zombie_override.new_prob - 1.0 / 11.0).abs() < 0.001);
    }

    #[test]
    fn test_user_overrides_highest_priority() {
        let global = default_priors();

        let signature = SupervisorSignature {
            name: "test-process".to_string(),
            category: None,
            confidence_weight: 0.9,
            notes: None,
            patterns: Default::default(),
            expected_lifetime: None,
            expected_cpu: None,
            priors: Some(SignaturePriors {
                useful: Some(BetaParams::new(10.0, 1.0)), // mean ~0.91
                useful_bad: None,
                abandoned: None,
                zombie: None,
            }),
        };

        let details = MatchDetails::default();
        let sig_match = SignatureMatch::new(&signature, MatchLevel::ExactCommand, details);

        let user_overrides = UserPriorOverrides {
            useful: Some(0.1), // Very low useful prior, overrides signature
            useful_bad: None,
            abandoned: None,
            zombie: None,
        };

        let context = PriorContext {
            global_priors: &global,
            signature_match: Some(&sig_match),
            user_overrides: Some(&user_overrides),
        };

        let resolved = resolve_priors(&context);
        assert_eq!(resolved.source_info.source, PriorSource::User);

        // User override should take precedence over signature
        assert!((resolved.priors.classes.useful.prior_prob - 0.1).abs() < 0.001);
    }

    #[test]
    fn test_prior_source_priority() {
        assert!(PriorSource::User.priority() > PriorSource::Signature.priority());
        assert!(PriorSource::Signature.priority() > PriorSource::Category.priority());
        assert!(PriorSource::Category.priority() > PriorSource::Global.priority());
    }

    #[test]
    fn test_overridden_prior_from_beta() {
        let beta = BetaParams::new(8.0, 2.0);
        let override_info = OverriddenPrior::from_beta_params(&beta, 0.5);

        assert!((override_info.original_prob - 0.5).abs() < 0.001);
        assert!((override_info.new_prob - 0.8).abs() < 0.001); // 8/(8+2) = 0.8
        assert_eq!(override_info.alpha, Some(8.0));
        assert_eq!(override_info.beta, Some(2.0));
    }

    #[test]
    fn test_match_level_to_string() {
        assert_eq!(match_level_to_string(&MatchLevel::None), "none");
        assert_eq!(
            match_level_to_string(&MatchLevel::MultiPattern),
            "multi_pattern"
        );
        assert_eq!(
            match_level_to_string(&MatchLevel::CommandOnly),
            "command_only"
        );
    }
}

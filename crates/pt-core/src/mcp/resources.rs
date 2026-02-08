//! MCP resource implementations.
//!
//! Resources expose read-only data: configuration, signatures, version info.

use crate::mcp::protocol::{ResourceContent, ResourceDefinition};

/// Build the list of available MCP resource definitions.
pub fn resource_definitions() -> Vec<ResourceDefinition> {
    vec![
        ResourceDefinition {
            uri: "pt://config/priors".to_string(),
            name: "Prior Configuration".to_string(),
            description: "Current Bayesian prior configuration for process scoring.".to_string(),
            mime_type: Some("application/json".to_string()),
        },
        ResourceDefinition {
            uri: "pt://config/policy".to_string(),
            name: "Policy Configuration".to_string(),
            description: "Current action policy and safety gates.".to_string(),
            mime_type: Some("application/json".to_string()),
        },
        ResourceDefinition {
            uri: "pt://signatures/builtin".to_string(),
            name: "Built-in Signatures".to_string(),
            description: "Built-in process signature library.".to_string(),
            mime_type: Some("application/json".to_string()),
        },
        ResourceDefinition {
            uri: "pt://version".to_string(),
            name: "Version Info".to_string(),
            description: "Process triage version and build information.".to_string(),
            mime_type: Some("application/json".to_string()),
        },
    ]
}

/// Read a resource by URI and return its content.
pub fn read_resource(uri: &str) -> Result<Vec<ResourceContent>, String> {
    match uri {
        "pt://config/priors" => resource_priors(uri),
        "pt://config/policy" => resource_policy(uri),
        "pt://signatures/builtin" => resource_signatures_builtin(uri),
        "pt://version" => resource_version(uri),
        _ => Err(format!("Unknown resource URI: {}", uri)),
    }
}

fn resource_priors(uri: &str) -> Result<Vec<ResourceContent>, String> {
    let options = crate::config::ConfigOptions::default();
    let config =
        crate::config::load_config(&options).map_err(|e| format!("Config load error: {}", e))?;

    let priors = serde_json::json!({
        "description": "Bayesian prior configuration for process scoring",
        "priors_path": config.priors_path.map(|p| p.display().to_string()),
        "priors_hash": config.priors_hash,
        "schema_version": config.priors.schema_version,
    });

    Ok(vec![ResourceContent {
        uri: uri.to_string(),
        mime_type: Some("application/json".to_string()),
        text: serde_json::to_string_pretty(&priors)
            .map_err(|e| format!("Serialization error: {}", e))?,
    }])
}

fn resource_policy(uri: &str) -> Result<Vec<ResourceContent>, String> {
    let options = crate::config::ConfigOptions::default();
    let config =
        crate::config::load_config(&options).map_err(|e| format!("Config load error: {}", e))?;

    let policy = serde_json::json!({
        "description": "Action policy and safety configuration",
        "policy_path": config.policy_path.map(|p| p.display().to_string()),
        "policy_hash": config.policy_hash,
        "schema_version": config.policy.schema_version,
    });

    Ok(vec![ResourceContent {
        uri: uri.to_string(),
        mime_type: Some("application/json".to_string()),
        text: serde_json::to_string_pretty(&policy)
            .map_err(|e| format!("Serialization error: {}", e))?,
    }])
}

fn resource_signatures_builtin(uri: &str) -> Result<Vec<ResourceContent>, String> {
    let mut db = crate::supervision::SignatureDatabase::new();
    db.add_default_signatures();

    let sigs: Vec<serde_json::Value> = db
        .signatures()
        .iter()
        .map(|s| {
            serde_json::json!({
                "name": s.name,
                "category": format!("{:?}", s.category),
                "priority": s.priority,
                "confidence": s.confidence_weight,
            })
        })
        .collect();

    let result = serde_json::json!({
        "count": sigs.len(),
        "signatures": sigs,
    });

    Ok(vec![ResourceContent {
        uri: uri.to_string(),
        mime_type: Some("application/json".to_string()),
        text: serde_json::to_string_pretty(&result)
            .map_err(|e| format!("Serialization error: {}", e))?,
    }])
}

fn resource_version(uri: &str) -> Result<Vec<ResourceContent>, String> {
    let result = serde_json::json!({
        "name": "process_triage",
        "version": env!("CARGO_PKG_VERSION"),
        "mcp_protocol": super::protocol::MCP_PROTOCOL_VERSION,
    });

    Ok(vec![ResourceContent {
        uri: uri.to_string(),
        mime_type: Some("application/json".to_string()),
        text: serde_json::to_string_pretty(&result)
            .map_err(|e| format!("Serialization error: {}", e))?,
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_definitions_not_empty() {
        let defs = resource_definitions();
        assert!(!defs.is_empty());
    }

    #[test]
    fn resource_definitions_have_uris() {
        for def in resource_definitions() {
            assert!(
                def.uri.starts_with("pt://"),
                "Resource '{}' missing pt:// prefix",
                def.uri
            );
        }
    }

    #[test]
    fn resource_definitions_have_json_mime() {
        for def in resource_definitions() {
            assert_eq!(
                def.mime_type.as_deref(),
                Some("application/json"),
                "Resource '{}' should be application/json",
                def.uri
            );
        }
    }

    #[test]
    fn read_unknown_resource_returns_error() {
        let result = read_resource("pt://nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn read_version_resource() {
        let result = read_resource("pt://version").unwrap();
        assert_eq!(result.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(&result[0].text).unwrap();
        assert_eq!(parsed["name"], "process_triage");
        assert!(parsed.get("version").is_some());
    }

    #[test]
    fn read_signatures_builtin_resource() {
        let result = read_resource("pt://signatures/builtin").unwrap();
        assert_eq!(result.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(&result[0].text).unwrap();
        assert!(parsed["count"].as_u64().unwrap() > 0);
    }

    #[test]
    fn read_priors_resource() {
        let result = read_resource("pt://config/priors").unwrap();
        assert_eq!(result.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(&result[0].text).unwrap();
        assert!(parsed.get("description").is_some());
    }

    #[test]
    fn read_policy_resource() {
        let result = read_resource("pt://config/policy").unwrap();
        assert_eq!(result.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(&result[0].text).unwrap();
        assert!(parsed.get("description").is_some());
    }

    #[test]
    fn resource_definitions_count() {
        let defs = resource_definitions();
        assert_eq!(defs.len(), 4);
    }
}

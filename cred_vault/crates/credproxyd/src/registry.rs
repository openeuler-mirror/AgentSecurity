//! fakecred → credential lookup for the data plane.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

use crate::config::Model;
use crate::policy::{self, HostPattern};

#[derive(Debug)]
pub struct Entry {
    /// fakecred as presented by the agent (raw form).
    pub fake_cred: String,
    /// Real secret, loaded from the vault at startup / management-plane swap.
    pub real_cred: String,
    /// Human-readable credential name (audit).
    pub name: String,
    pub user_id: String,
    pub user_name: String,
    /// Parsed `allowed_hosts`.
    pub hosts: Vec<HostPattern>,
}

#[derive(Debug, Default)]
pub struct Registry {
    by_fake_cred: HashMap<String, Arc<Entry>>,
}

impl Registry {
    pub fn build(model: &Model) -> Result<Self> {
        let mut by_fake_cred = HashMap::new();
        for credential in model.credentials.values() {
            let entry = Arc::new(Entry {
                fake_cred: credential.fake_cred.clone(),
                real_cred: credential.real_cred.clone(),
                name: credential.name.clone(),
                user_id: credential.user_id.clone(),
                user_name: credential.user_name.clone(),
                hosts: policy::parse_hosts(&credential.allowed_hosts)?,
            });
            by_fake_cred.insert(entry.fake_cred.clone(), entry);
        }
        Ok(Registry { by_fake_cred })
    }

    pub fn get(&self, fake_cred: &str) -> Option<&Arc<Entry>> {
        self.by_fake_cred.get(fake_cred)
    }

    pub fn len(&self) -> usize {
        self.by_fake_cred.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_fake_cred.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Credential, CredentialType, SCHEMA_VERSION};

    fn credential(name: &str, key: &str) -> Credential {
        Credential {
            schema_version: SCHEMA_VERSION,
            name: name.to_string(),
            kind: CredentialType::Https,
            user_id: "u-01".to_string(),
            user_name: "alice".to_string(),
            fake_cred: key.to_string(),
            real_cred: format!("real-{name}"),
            allowed_hosts: vec!["api.example.com".to_string()],
            rules: None,
        }
    }

    #[test]
    fn indexes_by_fakecred() {
        let mut credentials = std::collections::BTreeMap::new();
        credentials.insert(
            "fcred-0123456789abcdef0123456789abcdef".to_string(),
            credential("one", "fcred-0123456789abcdef0123456789abcdef"),
        );
        let model = Model {
            config: Default::default(),
            credentials,
        };
        let registry = Registry::build(&model).unwrap();
        assert_eq!(registry.len(), 1);
        let hit = registry
            .get("fcred-0123456789abcdef0123456789abcdef")
            .unwrap();
        assert_eq!(hit.name, "one");
        assert_eq!(hit.user_id, "u-01");
        assert!(policy::matches_any(&hit.hosts, "api.example.com"));
        assert!(registry
            .get("fcred-99999999999999999999999999999999")
            .is_none());
    }
}

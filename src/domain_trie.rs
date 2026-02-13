use std::collections::HashMap;

struct DomainTrieNode<V> {
    children: HashMap<String, DomainTrieNode<V>>,
    wildcard_value: Option<V>,
    exact_value: Option<V>,
}

/// Derives Default manually to avoid requiring V: Default, since all fields
/// default to empty/None regardless of V.
impl<V> Default for DomainTrieNode<V> {
    fn default() -> Self {
        Self {
            children: HashMap::new(),
            wildcard_value: None,
            exact_value: None,
        }
    }
}

/// Label-level trie for matching hostnames against domain patterns.
pub struct DomainTrie<V> {
    root: DomainTrieNode<V>,
}

impl<V> Default for DomainTrie<V> {
    fn default() -> Self {
        Self {
            root: DomainTrieNode::default(),
        }
    }
}

impl<V> DomainTrie<V> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a hostname pattern and associated value.
    ///
    /// Supported patterns:
    /// - `"example.com"` -- exact match only
    /// - `"*.example.com"` -- matches any subdomain, but not `example.com` itself
    /// - `".example.com"` -- matches both `example.com` and any subdomain
    /// - `"*"` -- catch-all, matches everything
    ///
    /// Returns the previous value for the same pattern slot, if any.
    pub fn insert(&mut self, pattern: &str, value: V) -> Option<V>
    where
        V: Clone,
    {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            let node = self.walk_to_node(suffix);
            node.wildcard_value.replace(value)
        } else if pattern == "*" {
            self.root.wildcard_value.replace(value)
        } else if let Some(suffix) = pattern.strip_prefix('.') {
            let node = self.walk_to_node(suffix);
            node.exact_value.replace(value.clone());
            node.wildcard_value.replace(value)
        } else {
            let node = self.walk_to_node(pattern);
            node.exact_value.replace(value)
        }
    }

    /// Returns a mutable reference to the value for a pattern, inserting
    /// `V::default()` if absent. Supports the same patterns as `insert`
    /// except `.`-shorthand (which sets two slots).
    pub fn entry_or_default(&mut self, pattern: &str) -> &mut V
    where
        V: Default,
    {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            let node = self.walk_to_node(suffix);
            node.wildcard_value.get_or_insert_with(V::default)
        } else if pattern == "*" {
            self.root.wildcard_value.get_or_insert_with(V::default)
        } else if pattern.starts_with('.') {
            panic!("entry_or_default does not support dot-shorthand patterns");
        } else {
            let node = self.walk_to_node(pattern);
            node.exact_value.get_or_insert_with(V::default)
        }
    }

    /// Walks (or creates) trie nodes for the given hostname, splitting by label
    /// in reverse order (TLD first), and returns the final node.
    fn walk_to_node(&mut self, hostname: &str) -> &mut DomainTrieNode<V> {
        let labels: Vec<&str> = hostname.split('.').rev().collect();
        let mut current = &mut self.root;
        for label in labels {
            current = current
                .children
                .entry(label.to_string())
                .or_insert_with(DomainTrieNode::default);
        }
        current
    }

    /// Looks up a hostname, returning the best matching value.
    /// Priority: exact match > deepest wildcard > no match.
    pub fn lookup(&self, hostname: &str) -> Option<&V> {
        if hostname.is_empty() {
            return None;
        }

        let labels: Vec<&str> = hostname.split('.').rev().collect();
        let mut current = &self.root;
        let mut best_wildcard: Option<&V> = self.root.wildcard_value.as_ref();

        for (i, label) in labels.iter().enumerate() {
            let is_last = i == labels.len() - 1;
            match current.children.get(*label) {
                Some(child) => {
                    current = child;
                    // Only record wildcards when more labels remain, since a wildcard
                    // on this node means "match any subdomain below here."
                    if !is_last {
                        if let Some(ref wv) = current.wildcard_value {
                            best_wildcard = Some(wv);
                        }
                    }
                }
                None => return best_wildcard,
            }
        }

        current.exact_value.as_ref().or(best_wildcard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_single_entry() {
        let mut t = DomainTrie::new();
        t.insert("example.com", 1);
        assert_eq!(t.lookup("example.com"), Some(&1));
    }

    #[test]
    fn exact_multiple_entries() {
        let mut t = DomainTrie::new();
        t.insert("a.example.com", 1);
        t.insert("b.example.com", 2);
        t.insert("other.net", 3);
        assert_eq!(t.lookup("a.example.com"), Some(&1));
        assert_eq!(t.lookup("b.example.com"), Some(&2));
        assert_eq!(t.lookup("other.net"), Some(&3));
    }

    #[test]
    fn exact_miss() {
        let mut t = DomainTrie::new();
        t.insert("example.com", 1);
        assert_eq!(t.lookup("other.com"), None);
        assert_eq!(t.lookup("sub.example.com"), None);
    }

    #[test]
    fn wildcard_matches_subdomain() {
        let mut t = DomainTrie::new();
        t.insert("*.example.com", 1);
        assert_eq!(t.lookup("foo.example.com"), Some(&1));
        assert_eq!(t.lookup("bar.example.com"), Some(&1));
    }

    #[test]
    fn wildcard_does_not_match_base_domain() {
        let mut t = DomainTrie::new();
        t.insert("*.example.com", 1);
        assert_eq!(t.lookup("example.com"), None);
    }

    #[test]
    fn wildcard_matches_deep_subdomain() {
        let mut t = DomainTrie::new();
        t.insert("*.example.com", 1);
        assert_eq!(t.lookup("a.b.c.example.com"), Some(&1));
    }

    #[test]
    fn exact_wins_over_wildcard() {
        let mut t = DomainTrie::new();
        t.insert("*.example.com", 1);
        t.insert("api.example.com", 2);
        assert_eq!(t.lookup("api.example.com"), Some(&2));
        assert_eq!(t.lookup("other.example.com"), Some(&1));
    }

    #[test]
    fn deeper_wildcard_wins() {
        let mut t = DomainTrie::new();
        t.insert("*.example.com", 1);
        t.insert("*.api.example.com", 2);
        assert_eq!(t.lookup("v1.api.example.com"), Some(&2));
        assert_eq!(t.lookup("foo.example.com"), Some(&1));
    }

    #[test]
    fn deep_subdomain_falls_back_to_shallowest_wildcard() {
        let mut t = DomainTrie::new();
        t.insert("*.example.com", 1);
        assert_eq!(t.lookup("x.y.z.example.com"), Some(&1));
    }

    #[test]
    fn exact_and_wildcard_on_same_domain() {
        let mut t = DomainTrie::new();
        t.insert("example.com", 1);
        t.insert("*.example.com", 2);
        assert_eq!(t.lookup("example.com"), Some(&1));
        assert_eq!(t.lookup("foo.example.com"), Some(&2));
    }

    #[test]
    fn multiple_wildcards_at_different_depths() {
        let mut t = DomainTrie::new();
        t.insert("*.com", 1);
        t.insert("*.example.com", 2);
        t.insert("*.api.example.com", 3);

        assert_eq!(t.lookup("random.com"), Some(&1));
        assert_eq!(t.lookup("foo.example.com"), Some(&2));
        assert_eq!(t.lookup("v1.api.example.com"), Some(&3));
        // "api.example.com" walks: com -> example (wildcard=2) -> api (wildcard=3).
        // No exact at api node, so best wildcard is *.example.com (2).
        assert_eq!(t.lookup("api.example.com"), Some(&2));
    }

    #[test]
    fn empty_hostname() {
        let t: DomainTrie<i32> = DomainTrie::new();
        assert_eq!(t.lookup(""), None);
    }

    #[test]
    fn single_label_hostname() {
        let mut t = DomainTrie::new();
        t.insert("localhost", 1);
        assert_eq!(t.lookup("localhost"), Some(&1));
        assert_eq!(t.lookup("other"), None);
    }

    #[test]
    fn root_wildcard() {
        let mut t = DomainTrie::new();
        t.insert("*", 1);
        assert_eq!(t.lookup("anything.example.com"), Some(&1));
        assert_eq!(t.lookup("localhost"), Some(&1));
    }

    #[test]
    fn root_wildcard_with_specific_override() {
        let mut t = DomainTrie::new();
        t.insert("*", 1);
        t.insert("special.com", 2);
        assert_eq!(t.lookup("special.com"), Some(&2));
        assert_eq!(t.lookup("other.com"), Some(&1));
    }

    #[test]
    fn duplicate_insert_replaces() {
        let mut t = DomainTrie::new();
        assert_eq!(t.insert("example.com", 1), None);
        assert_eq!(t.insert("example.com", 2), Some(1));
        assert_eq!(t.lookup("example.com"), Some(&2));
    }

    #[test]
    fn duplicate_wildcard_insert_replaces() {
        let mut t = DomainTrie::new();
        assert_eq!(t.insert("*.example.com", 1), None);
        assert_eq!(t.insert("*.example.com", 2), Some(1));
        assert_eq!(t.lookup("foo.example.com"), Some(&2));
    }

    #[test]
    fn no_partial_label_match() {
        let mut t = DomainTrie::new();
        t.insert("*.example.com", 1);
        assert_eq!(t.lookup("foo.exampleX.com"), None);
    }

    #[test]
    fn wildcard_only_no_exact() {
        let mut t = DomainTrie::new();
        t.insert("*.example.com", 1);
        assert_eq!(t.lookup("example.com"), None);
        assert_eq!(t.lookup("www.example.com"), Some(&1));
    }

    #[test]
    fn exact_only_no_wildcard() {
        let mut t = DomainTrie::new();
        t.insert("api.example.com", 1);
        assert_eq!(t.lookup("api.example.com"), Some(&1));
        assert_eq!(t.lookup("v1.api.example.com"), None);
    }

    #[test]
    fn deeper_exact_with_shallower_wildcard() {
        let mut t = DomainTrie::new();
        t.insert("*.example.com", 1);
        t.insert("api.example.com", 2);
        assert_eq!(t.lookup("api.example.com"), Some(&2));
        // Sub-subdomain of api falls back to *.example.com since no wildcard at api level
        assert_eq!(t.lookup("v1.api.example.com"), Some(&1));
    }

    #[test]
    fn deeper_exact_with_deeper_wildcard() {
        let mut t = DomainTrie::new();
        t.insert("*.example.com", 1);
        t.insert("*.api.example.com", 2);
        t.insert("special.api.example.com", 3);
        assert_eq!(t.lookup("special.api.example.com"), Some(&3));
        assert_eq!(t.lookup("other.api.example.com"), Some(&2));
        assert_eq!(t.lookup("foo.example.com"), Some(&1));
    }

    #[test]
    fn dot_shorthand_matches_base_domain() {
        let mut t = DomainTrie::new();
        t.insert(".example.com", 1);
        assert_eq!(t.lookup("example.com"), Some(&1));
    }

    #[test]
    fn dot_shorthand_matches_subdomain() {
        let mut t = DomainTrie::new();
        t.insert(".example.com", 1);
        assert_eq!(t.lookup("foo.example.com"), Some(&1));
        assert_eq!(t.lookup("bar.example.com"), Some(&1));
    }

    #[test]
    fn dot_shorthand_matches_deep_subdomain() {
        let mut t = DomainTrie::new();
        t.insert(".example.com", 1);
        assert_eq!(t.lookup("a.b.c.example.com"), Some(&1));
    }

    #[test]
    fn dot_shorthand_does_not_match_unrelated() {
        let mut t = DomainTrie::new();
        t.insert(".example.com", 1);
        assert_eq!(t.lookup("other.com"), None);
        assert_eq!(t.lookup("com"), None);
    }

    #[test]
    fn dot_shorthand_exact_overrides() {
        let mut t = DomainTrie::new();
        t.insert(".example.com", 1);
        t.insert("api.example.com", 2);
        assert_eq!(t.lookup("api.example.com"), Some(&2));
        assert_eq!(t.lookup("example.com"), Some(&1));
        assert_eq!(t.lookup("www.example.com"), Some(&1));
    }

    #[test]
    fn dot_shorthand_wildcard_overrides() {
        let mut t = DomainTrie::new();
        t.insert(".example.com", 1);
        t.insert("*.api.example.com", 2);
        assert_eq!(t.lookup("v1.api.example.com"), Some(&2));
        assert_eq!(t.lookup("example.com"), Some(&1));
        assert_eq!(t.lookup("foo.example.com"), Some(&1));
    }

    #[test]
    fn dot_shorthand_replaces_previous_exact_and_wildcard() {
        let mut t = DomainTrie::new();
        t.insert("example.com", 1);
        t.insert("*.example.com", 2);
        t.insert(".example.com", 3);
        assert_eq!(t.lookup("example.com"), Some(&3));
        assert_eq!(t.lookup("foo.example.com"), Some(&3));
    }

    #[test]
    fn dot_shorthand_replaced_by_exact_and_wildcard() {
        let mut t = DomainTrie::new();
        t.insert(".example.com", 1);
        t.insert("example.com", 2);
        t.insert("*.example.com", 3);
        assert_eq!(t.lookup("example.com"), Some(&2));
        assert_eq!(t.lookup("foo.example.com"), Some(&3));
    }

    #[test]
    fn dot_shorthand_duplicate_replaces() {
        let mut t = DomainTrie::new();
        assert_eq!(t.insert(".example.com", 1), None);
        assert_eq!(t.insert(".example.com", 2), Some(1));
        assert_eq!(t.lookup("example.com"), Some(&2));
        assert_eq!(t.lookup("foo.example.com"), Some(&2));
    }

    #[test]
    fn entry_or_default_creates_and_returns_mut() {
        let mut t: DomainTrie<Vec<i32>> = DomainTrie::new();
        t.entry_or_default("example.com").push(1);
        t.entry_or_default("example.com").push(2);
        assert_eq!(t.lookup("example.com"), Some(&vec![1, 2]));
    }

    #[test]
    fn entry_or_default_wildcard() {
        let mut t: DomainTrie<Vec<i32>> = DomainTrie::new();
        t.entry_or_default("*.example.com").push(10);
        t.entry_or_default("*.example.com").push(20);
        assert_eq!(t.lookup("foo.example.com"), Some(&vec![10, 20]));
        assert_eq!(t.lookup("example.com"), None);
    }

    #[test]
    fn entry_or_default_root_wildcard() {
        let mut t: DomainTrie<Vec<i32>> = DomainTrie::new();
        t.entry_or_default("*").push(1);
        t.entry_or_default("*").push(2);
        assert_eq!(t.lookup("anything.com"), Some(&vec![1, 2]));
    }
}

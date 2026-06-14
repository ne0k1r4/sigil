/// Tests for the new config-driven features: user config file (~/.sigil.toml),
/// custom signature rule engine, and imphash clustering.

// ── user config ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod config {
    use sigil::config::SigilConfig;

    #[test]
    fn default_config_is_empty() {
        let cfg = SigilConfig::default();
        assert!(cfg.antidebug_imports.is_empty());
        assert!(cfg.antidebug_strings.is_empty());
        assert!(cfg.anticheat_imports.is_empty());
        assert!(cfg.anticheat_strings.is_empty());
        assert!(cfg.known_imphashes.is_empty());
    }

    #[test]
    fn parses_well_formed_toml() {
        let toml_str = r#"
[[antidebug_imports]]
pattern = "MyDebugCheck"
description = "Internal debug check"

[[anticheat_strings]]
pattern = "myac_driver.sys"
description = "Internal AC driver"

[[known_imphashes]]
pattern = "deadbeefdeadbeefdeadbeefdeadbeef"
description = "Internal threat intel hash"
"#;
        let cfg: SigilConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.antidebug_imports.len(), 1);
        assert_eq!(cfg.antidebug_imports[0].pattern, "MyDebugCheck");
        assert_eq!(cfg.anticheat_strings.len(), 1);
        assert_eq!(cfg.known_imphashes[0].pattern, "deadbeefdeadbeefdeadbeefdeadbeef");
    }

    #[test]
    fn empty_toml_yields_default() {
        let cfg: SigilConfig = toml::from_str("").unwrap();
        assert!(cfg.antidebug_imports.is_empty());
    }
}

// ── custom rule engine ───────────────────────────────────────────────────────

#[cfg(test)]
mod rules {
    use sigil::rules::{scan_rules, RuleFile};

    #[test]
    fn string_match_rule_hits() {
        let toml_str = r#"
[[rules]]
name = "Custom AC reference"
category = "anti-cheat"
string_match = "myac_driver"
case_insensitive = true
"#;
        let rf: RuleFile = toml::from_str(toml_str).unwrap();
        let strings = vec!["c:\\drivers\\MyAC_Driver.sys".to_string()];
        let hits = scan_rules(&rf, &[], &strings);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].category, "anti-cheat");
        assert_eq!(hits[0].technique, "Custom AC reference");
    }

    #[test]
    fn string_match_case_sensitive_miss() {
        let toml_str = r#"
[[rules]]
name = "Case sensitive rule"
string_match = "EXACT"
case_insensitive = false
"#;
        let rf: RuleFile = toml::from_str(toml_str).unwrap();
        let strings = vec!["exact".to_string()]; // different case
        let hits = scan_rules(&rf, &[], &strings);
        assert!(hits.is_empty());
    }

    #[test]
    fn hex_pattern_rule_hits() {
        let toml_str = r#"
[[rules]]
name = "Custom shellcode stub"
category = "shellcode"
hex_pattern = "90 90 CC"
"#;
        let rf: RuleFile = toml::from_str(toml_str).unwrap();
        let data = vec![0x00, 0x90, 0x90, 0xCC, 0x00];
        let hits = scan_rules(&rf, &data, &[]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].category, "shellcode");
    }

    #[test]
    fn invalid_hex_pattern_warns_but_does_not_panic() {
        let toml_str = r#"
[[rules]]
name = "Broken rule"
hex_pattern = "ZZ ZZ"
"#;
        let rf: RuleFile = toml::from_str(toml_str).unwrap();
        let data = vec![0x00, 0x01];
        let hits = scan_rules(&rf, &data, &[]);
        assert!(hits.is_empty(), "invalid pattern should produce no hits, not panic");
    }

    #[test]
    fn empty_rules_produce_no_hits() {
        let rf = RuleFile::default();
        let hits = scan_rules(&rf, &[1,2,3], &["hello".to_string()]);
        assert!(hits.is_empty());
    }
}

// ── imphash clustering ──────────────────────────────────────────────────────

#[cfg(test)]
mod imphash {
    use sigil::config::SigEntry;
    use sigil::sigs::check_imphash;

    #[test]
    fn unknown_hash_returns_none() {
        let result = check_imphash("0000000000000000000000000000000", &[]);
        assert!(result.is_none());
    }

    #[test]
    fn custom_imphash_matches() {
        let extra = vec![SigEntry {
            pattern: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            description: "Internal threat intel hash".to_string(),
        }];
        let result = check_imphash("deadbeefdeadbeefdeadbeefdeadbeef", &extra);
        assert!(result.is_some());
        assert!(result.unwrap().contains("Internal threat intel hash"));
    }

    #[test]
    fn custom_imphash_case_insensitive() {
        let extra = vec![SigEntry {
            pattern: "DEADBEEFDEADBEEFDEADBEEFDEADBEEF".to_string(),
            description: "Upper-case stored hash".to_string(),
        }];
        let result = check_imphash("deadbeefdeadbeefdeadbeefdeadbeef", &extra);
        assert!(result.is_some());
    }
}

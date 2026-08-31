use regex::Regex;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub path: String,
    pub category: String,
    pub safety: String,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RulesFile {
    rules: Vec<Rule>,
}

pub struct Classifier {
    /// Fast path: (prefix, category, safety, exclude_regexes) for rules without wildcards
    pub prefix_rules: Vec<(String, String, String, Vec<Regex>)>,
    /// Slow path: (regex, category, safety, exclude_regexes) for rules with *, ?, []
    pub pattern_rules: Vec<(Regex, String, String, Vec<Regex>)>,
}

impl Classifier {
    pub fn from_yaml(rules_path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(rules_path)?;
        let rules_file: RulesFile = serde_yml::from_str(&content)?;

        let mut prefix_rules = Vec::new();
        let mut pattern_rules = Vec::new();

        for rule in &rules_file.rules {
            let expanded = shellexpand::tilde(&rule.path).to_string();
            let has_wildcard = expanded.contains(&['*', '?', '['][..]);

            let exclude_regexes: Vec<Regex> = rule
                .exclude_patterns
                .iter()
                .map(|ep| {
                    let ep_expanded = shellexpand::tilde(ep).to_string();
                    glob_to_regex(&ep_expanded)
                })
                .filter_map(|r| r.ok())
                .collect();

            if has_wildcard {
                let regex = glob_to_regex(&expanded);
                if let Ok(re) = regex {
                    pattern_rules.push((re, rule.category.clone(), rule.safety.clone(), exclude_regexes));
                }
            } else {
                prefix_rules.push((expanded, rule.category.clone(), rule.safety.clone(), exclude_regexes));
            }
        }

        // Sort prefix rules by length descending for greedy (most specific first)
        prefix_rules.sort_by_key(|a| std::cmp::Reverse(a.0.len()));

        Ok(Classifier {
            prefix_rules,
            pattern_rules,
        })
    }

    /// Returns (category, safety) for a given file path.
    /// Prefix rules checked first (fast), then regex rules.
    pub fn classify(&self, filepath: &str) -> (String, String) {
        // 1. Fast path: prefix matching (O(n) but n is small, no regex overhead)
        for (prefix, cat, safety, exclude_regexes) in &self.prefix_rules {
            if filepath.starts_with(prefix.as_str())
                && (filepath.len() == prefix.len()
                    || filepath.as_bytes()[prefix.len()] == b'/')
            {
                if exclude_regexes.iter().any(|re| re.is_match(filepath)) {
                    continue;
                }
                return (cat.clone(), safety.clone());
            }
        }

        // 2. Slow path: regex matching for wildcard rules
        for (regex, cat, safety, exclude_regexes) in &self.pattern_rules {
            if regex.is_match(filepath) {
                if exclude_regexes.iter().any(|re| re.is_match(filepath)) {
                    continue;
                }
                return (cat.clone(), safety.clone());
            }
        }

        ("".to_string(), "Safe".to_string())
    }
}

/// Convert a glob-like pattern to a regex.
///   * `*` matches any characters except `/` (single path component)
///   * `?` matches any single character except `/`
///   * `[abc]` character classes are passed through
///
/// Special regex chars (`.+^$(){}|`) are escaped.
fn glob_to_regex(pattern: &str) -> anyhow::Result<Regex> {
    let mut regex = String::from("^");
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => {
                regex.push_str("[^/]*");
            }
            '?' => {
                regex.push_str("[^/]");
            }
            '[' => {
                let mut j = i + 1;
                let mut closed = false;
                while j < chars.len() {
                    if chars[j] == ']' {
                        for &c in &chars[i..=j] {
                            regex.push(c);
                        }
                        i = j;
                        closed = true;
                        break;
                    }
                    j += 1;
                }
                if !closed {
                    regex.push('\\');
                    regex.push('[');
                }
            }
            // Escape special regex characters
            '.' | '+' | '^' | '$' | '(' | ')' | '{' | '}' | '|' | '\\' => {
                regex.push('\\');
                regex.push(chars[i]);
            }
            _ => {
                regex.push(chars[i]);
            }
        }
        i += 1;
    }
    regex.push('$');
    Ok(Regex::new(&regex)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_to_regex_star() {
        let re = glob_to_regex("/var/log/*.log").unwrap();
        assert!(re.is_match("/var/log/auth.log"));
        assert!(re.is_match("/var/log/kern.log"));
        assert!(!re.is_match("/var/log/syslog")); // syslog doesn't end with .log
        assert!(!re.is_match("/var/log/subdir/syslog")); // * doesn't cross /
    }

    #[test]
    fn test_glob_to_regex_question() {
        let re = glob_to_regex("/tmp/file?.txt").unwrap();
        assert!(re.is_match("/tmp/file1.txt"));
        assert!(re.is_match("/tmp/fileA.txt"));
        assert!(!re.is_match("/tmp/file10.txt"));
    }

    #[test]
    fn test_glob_to_regex_exact() {
        let re = glob_to_regex("/var/cache/apt").unwrap();
        assert!(re.is_match("/var/cache/apt"));
        assert!(!re.is_match("/var/cache/apt/archives/pkg.deb"));
    }

    fn empty_excludes() -> Vec<Regex> { vec![] }

    #[test]
    fn test_classify_prefix_rule() {
        let c = Classifier {
            prefix_rules: vec![("/var/log".into(), "日志".into(), "Safe".into(), empty_excludes())],
            pattern_rules: vec![],
        };
        let (cat, _) = c.classify("/var/log/syslog");
        assert_eq!(cat, "日志");
    }

    #[test]
    fn test_classify_wildcard_rule() {
        let re = glob_to_regex("/var/log/*.log").unwrap();
        let c = Classifier {
            prefix_rules: vec![],
            pattern_rules: vec![(re, "系统日志".into(), "Safe".into(), empty_excludes())],
        };
        let (cat, _) = c.classify("/var/log/auth.log");
        assert_eq!(cat, "系统日志");
    }

    #[test]
    fn test_classify_no_match() {
        let c = Classifier {
            prefix_rules: vec![],
            pattern_rules: vec![],
        };
        let (cat, safety) = c.classify("/etc/passwd");
        assert_eq!(cat, "");
        assert_eq!(safety, "Safe");
    }

    #[test]
    fn test_classify_prefix_takes_priority() {
        let re = glob_to_regex("/var/log/*.log").unwrap();
        let c = Classifier {
            prefix_rules: vec![("/var/log/syslog".into(), "特定日志".into(), "Caution".into(), empty_excludes())],
            pattern_rules: vec![(re, "系统日志".into(), "Safe".into(), empty_excludes())],
        };
        let (cat, safety) = c.classify("/var/log/syslog");
        assert_eq!(cat, "特定日志"); // more specific prefix wins
        assert_eq!(safety, "Caution");
    }

    #[test]
    fn test_wildcard_tmp_star() {
        let re = glob_to_regex("/tmp/*").unwrap();
        let c = Classifier {
            prefix_rules: vec![],
            pattern_rules: vec![(re, "临时文件".into(), "Safe".into(), empty_excludes())],
        };
        assert_eq!(c.classify("/tmp/test.txt").0, "临时文件");
        assert_eq!(c.classify("/tmp/subdir").0, "临时文件");
        assert_eq!(c.classify("/tmp/subdir/file").0, ""); // depth limit by * 
    }

    #[test]
    fn test_classify_exclude_pattern() {
        let re = glob_to_regex("/var/log/*.log").unwrap();
        let wtmp_re = glob_to_regex("/var/log/wtmp").unwrap();
        let btmp_re = glob_to_regex("/var/log/btmp").unwrap();
        let c = Classifier {
            prefix_rules: vec![],
            pattern_rules: vec![(re, "系统日志".into(), "Safe".into(), vec![wtmp_re, btmp_re])],
        };
        // auth.log matches the rule and is not excluded
        assert_eq!(c.classify("/var/log/auth.log").0, "系统日志");
        // wtmp matches the rule but is excluded
        assert_eq!(c.classify("/var/log/wtmp").0, "");
        // btmp matches the rule but is excluded
        assert_eq!(c.classify("/var/log/btmp").0, "");
    }

    #[test]
    fn test_classify_exclude_pattern_wildcard() {
        let re = glob_to_regex("/tmp/*").unwrap();
        let lock_re = glob_to_regex("/tmp/.X*-lock").unwrap();
        let c = Classifier {
            prefix_rules: vec![],
            pattern_rules: vec![(re, "临时文件".into(), "Safe".into(), vec![lock_re])],
        };
        assert_eq!(c.classify("/tmp/test.txt").0, "临时文件");
        assert_eq!(c.classify("/tmp/.X11-lock").0, "");
    }
}

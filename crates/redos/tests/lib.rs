#[cfg(test)]
mod tests {
    use redos::vulnerabilities;

    static SAFE: &str = include_str!("safe.txt");

    /// Takes a test file and returns pairs
    /// of test names and their contents
    fn parse_test_file(file: &str) -> Vec<(String, Vec<String>)> {
        let mut tests: Vec<(String, Vec<String>)> = vec![];

        for line in file.lines() {
            if line.starts_with('#') {
                continue;
            }

            if line.starts_with('\t') {
                let mut line = line.to_string();
                line.remove(0);
                tests.last_mut().unwrap().1.push(line);
            } else {
                tests.push((line.to_string(), vec![]));
            }
        }

        tests
    }

    fn assert_safe(regex: &str, message: &str) {
        let vulnerabilities =
            vulnerabilities(regex, &Default::default()).map(|r| r.vulnerabilities);

        assert!(
            vulnerabilities.is_ok(),
            "{} failed to get vulnerabilities: {}",
            message,
            regex
        );

        assert_eq!(
            vulnerabilities.unwrap(),
            vec![],
            "{} was not safe: {}",
            message,
            regex
        );
    }

    #[test]
    fn check_safe() {
        let test_suite = parse_test_file(SAFE);
        assert!(!test_suite.is_empty());
        for (name, tests) in test_suite {
            assert!(!tests.is_empty());
            for test in tests {
                assert_safe(&test, &name);
            }
        }
    }
}

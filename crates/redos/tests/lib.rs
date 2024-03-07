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
                line.pop();
                tests.last_mut().unwrap().1.push(line);
            } else {
                tests.push((line.to_string(), vec![]));
            }
        }

        tests
    }

    fn assert_safe(regex: &str, message: &str) {
        assert_eq!(
            vulnerabilities(regex, &Default::default())
                .unwrap()
                .vulnerabilities,
            vec![],
            "{} failed: {}",
            message,
            regex
        );
    }

    #[test]
    fn check_safe() {
        for (name, tests) in parse_test_file(SAFE) {
            for test in tests {
                assert_safe(&test, &name);
            }
        }
    }
}

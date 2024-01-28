#[cfg(test)]
mod tests {
    use redos::vulnerabilities;

    fn assert_safe(regex: &str) {
        assert_eq!(
            vulnerabilities(regex, &Default::default())
                .unwrap()
                .vulnerabilities,
            vec![]
        );
    }

    #[test]
    fn trivial_regexes() {
        assert_safe("abc");
        assert_safe("(abc|def)|[nhi]?");
        assert_safe("a{1,43}");
    }
}

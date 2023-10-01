#[cfg(test)]
mod tests {
    use redos::vulnerabilities;

    fn assert_safe(regex: &str) {
        assert_eq!(vulnerabilities(regex), vec![]);
    }

    #[test]
    fn trivial_regexes() {
        assert_safe("abc");
        assert_safe("(abc|def)|[nhi]?");
    }
}

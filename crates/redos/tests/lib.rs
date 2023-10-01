#[cfg(test)]
mod tests {
    use redos::vulnerabilities;

    #[test]
    fn test() {
        let re = vulnerabilities!("a+");
    }
}

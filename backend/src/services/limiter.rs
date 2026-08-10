pub fn parse_rate_limit(s: &str) -> (u32, std::time::Duration) {
    let parts: Vec<&str> = s.split('/').collect();
    let count = parts.first().and_then(|s| s.parse().ok()).unwrap_or(100);
    let period = parts.get(1).map(|p| match *p {
        "second" => std::time::Duration::from_secs(1),
        "minute" => std::time::Duration::from_secs(60),
        "hour" => std::time::Duration::from_secs(3600),
        "day" => std::time::Duration::from_secs(86400),
        _ => std::time::Duration::from_secs(3600),
    });
    (count, period.unwrap_or(std::time::Duration::from_secs(3600)))
}

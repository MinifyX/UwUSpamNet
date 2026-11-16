use serde_json::Value;
use uwuspamnet::digest;

#[test]
fn test_vectors() {
    let file = include_str!("../../docs/digest-v1-vectors.json");
    let vectors: Value = serde_json::from_str(file).unwrap();
    let vectors = vectors["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 10);
    for v in vectors {
        let input = v["input"].as_str().unwrap();
        let name = v["name"].as_str().unwrap();
        assert_eq!(digest::normalize(input), v["normalized"], "{name}");
        let want: Vec<String> = serde_json::from_value(v["digests"].clone()).unwrap();
        assert_eq!(digest::digests(input), want, "{name}");
        assert!(want.iter().all(|d| digest::is_valid(d)), "{name}");
    }
}

#[test]
fn validity() {
    assert!(digest::is_valid("d1:0123456789abcdef0123456789abcdef"));
    assert!(digest::is_valid("p1:0123456789abcdef0123456789abcdef"));
    assert!(!digest::is_valid("d1:0123456789ABCDEF0123456789abcdef"));
    assert!(!digest::is_valid("d2:0123456789abcdef0123456789abcdef"));
    assert!(!digest::is_valid("d1:0123"));
}

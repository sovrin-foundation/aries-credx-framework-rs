#![deny(
    warnings,
    missing_docs,
    unsafe_code,
    unused_import_braces,
    unused_lifetimes,
    unused_qualifications,
)]
//! Aries credential exchange framework facilitates anonymous credential issuance and presentations

/// Encodings that are used by mappings to transform input attribute data
/// of a specific format into a integer suitable for cryptographic signing.
pub mod encoding;
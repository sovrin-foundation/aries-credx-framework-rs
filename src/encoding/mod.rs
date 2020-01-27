/// Represents an abstract encoder used for converting types to cryptographic integers
pub trait AttributeEncoder {
    /// The type to represent the cryptographic integer
    type Output;

    /// Takes an date string that is formatted according to RFC3339
    /// and converts it to a cryptographic integer. 
    /// `value`: Any type that can be converted into a string slice
    fn from_rfc3339<'a, A: Into<&'a str>>(value: A) -> Result<Self::Output, String>;
    /// Takes a 64-bit floating point number and converts it into
    /// a cryptographic integer
    /// `value`: Any type that can be converted into a f64
    fn from_f64<A: Into<f64>>(value: A) -> Result<Self::Output, String>;
    /// Takes a signed number and converts it into
    /// a cryptographic integer
    /// `value`: Any type that can be converted into a isize
    fn from_isize<A: Into<isize>>(value: A) -> Result<Self::Output, String>;

    /// Takes an unsigned number and converts it into
    /// a cryptographic integer
    /// `value`: Any type that can be converted into a usize
    fn from_usize<A: Into<usize>>(value: A) -> Result<Self::Output, String>;
}

/// Provides an encoder to BLS12-381 FieldElements
#[cfg(feature = "bls381")]
pub mod bls381_fieldelem;

/// Provides an encoder to openssl's BIGNUM
#[cfg(feature = "rsa-native")]
pub mod rsa_native;
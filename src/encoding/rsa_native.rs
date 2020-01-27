use super::AttributeEncoder;

use chrono::DateTime;
use openssl::{
    bn::{BigNum, BigNumRef}
};

/// How many bits are used to shift 1 to get to zero centering
pub const BITS_IN_ZERO: i32 = 254;

/// 2^BITS_IN_ZERO. Zero centers numbers used as ECC field elements
/// Should only be used where comparisons are used
fn zero() -> BigNum {
    let mut bn = BigNum::from_u32(1).unwrap();
    bn.set_bit(BITS_IN_ZERO).unwrap();
    bn
} 

fn max() -> BigNum {
    BigNum::from_hex_str("FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFFF_FFFFFFFF").unwrap()
}

/// Represents an integer than can be cryptographically signed
pub struct OpenSslAttributeEncoder;

impl AttributeEncoder for OpenSslAttributeEncoder {
    type Output = BigNum;

    /// Takes an date string that is formatted according to RFC3339
    /// and converts it to a cryptographic integer. 
    /// `value`: Any type that can be converted into a string slice
    fn from_rfc3339<'a, A: Into<&'a str>>(value: A) -> Result<Self::Output, String> {
        let dt = DateTime::parse_from_rfc3339(value.into()).map_err(|e| format!("{:?}", e))?;
        Self::from_usize(dt.timestamp() as usize)
    }

    /// Takes a 64-bit floating point number and converts it into
    /// a cryptographic integer
    /// `value`: Any type that can be converted into a f64
    fn from_f64<A: Into<f64>>(value: A) -> Result<Self::Output, String> {
        use std::num::FpCategory::*;
        use num_bigint::Sign::*;

        let value = value.into();

        Ok(
        match value.classify() {
            Nan => BigNum::from_u32(1).unwrap(),
            Subnormal => BigNum::from_u32(2).unwrap(),
            Zero => zero(),
            Infinite => {
                if value.is_sign_positive() {
                    sub(&max(), &BigNum::from_u32(9).unwrap())
                } else {
                    BigNum::from_u32(8).unwrap()
                }
            },
            Normal => {
                let mut b = bigdecimal::BigDecimal::from(value);

                for _ in 0..BITS_IN_ZERO {
                    b = b.double();
                }
                let (bi, _) = b.into_bigint_and_exponent();
                let (sign, bytes) = bi.to_bytes_be();
                let f = BigNum::from_slice(bytes.as_slice()).unwrap();
                match sign {
                    NoSign => zero(),
                    Plus => f,
                    Minus => sub(&zero(), &f)
                }
            }
        })
    }

    /// Takes a signed number and converts it into
    /// a cryptographic integer
    /// `value`: Any type that can be converted into a isize
    fn from_isize<A: Into<isize>>(value: A) -> Result<Self::Output, String> {
        let value = value.into();
        if value < 0 {
            let value = -value as u64;
            Ok(sub(&zero(), &u64_to_bignum(value)))
        } else {
            Self::from_usize(value as usize)
        }
    }

    /// Takes an unsigned number and converts it into
    /// a cryptographic integer
    /// `value`: Any type that can be converted into a usize
    fn from_usize<A: Into<usize>>(value: A) -> Result<Self::Output, String> {
        Ok(add(&zero(), &u64_to_bignum(value.into() as u64)))
    }
}

fn u64_to_bignum(v: u64) -> BigNum {
    BigNum::from_dec_str(&format!("{}", v)).unwrap()
}

fn add(a: &BigNumRef, b: &BigNumRef) -> BigNum {
    let mut bn = BigNum::new().unwrap();
    BigNumRef::checked_add(&mut bn, &a, &b).unwrap();
    bn
}

fn sub(a: &BigNumRef, b: &BigNumRef) -> BigNum {
    let mut bn = BigNum::new().unwrap();
    BigNumRef::checked_sub(&mut bn, &a, &b).unwrap();
    bn
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_string_convert() {
        let res = OpenSslAttributeEncoder::from_rfc3339("2018-01-26T18:30:09.453+00:00");
        assert!(res.is_ok());
        assert_eq!(add(&BigNum::from_u32(1_516_991_409u32).unwrap(), &zero()), res.unwrap());

        let res = OpenSslAttributeEncoder::from_rfc3339("2020-01-26T00:30:09.000+18:00");
        assert!(res.is_ok());
        assert_eq!(add(&BigNum::from_u32(1_579_933_809u32).unwrap(), &zero()), res.unwrap());

        let res = OpenSslAttributeEncoder::from_rfc3339("1970-01-01T00:00:00.000+00:00");
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), zero());

        let res = OpenSslAttributeEncoder::from_rfc3339("1900");
        assert!(res.is_err());
    }

    #[test]
    fn decimal_test() {
        let res1 = OpenSslAttributeEncoder::from_f64(1.33f32);
        assert!(res1.is_ok());
        let res2 = OpenSslAttributeEncoder::from_f64(-1.33f32);
        assert!(res2.is_ok());
        assert_eq!(zero(), add(&res1.unwrap(), &res2.unwrap()));

        let res1 = OpenSslAttributeEncoder::from_f64(std::f64::MAX);
        assert!(res1.is_ok());
        let res2 = res1.unwrap();
        assert_eq!(sub(&res2, &res2), BigNum::new().unwrap());

        let res3 = OpenSslAttributeEncoder::from_f64(std::f64::MIN);
        assert!(res3.is_ok());
        assert_eq!(zero(), add(&res3.unwrap(), &res2));

        let res1 = OpenSslAttributeEncoder::from_f64(std::f64::NEG_INFINITY);
        assert!(res1.is_ok());
        assert_eq!(BigNum::from_u32(8).unwrap(), res1.unwrap());

        let pos_inf = sub(&max(), &BigNum::from_u32(9).unwrap());
        let res1 = OpenSslAttributeEncoder::from_f64(std::f64::INFINITY);
        assert!(res1.is_ok());
        assert_eq!(pos_inf, res1.unwrap());

        let res1 = OpenSslAttributeEncoder::from_f64(std::f64::NAN);
        assert!(res1.is_ok());
        assert_eq!(BigNum::from_u32(1).unwrap(), res1.unwrap());
    }

    #[test]
    fn size_test() {
        let res = OpenSslAttributeEncoder::from_isize(0isize);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), zero());
        let res = OpenSslAttributeEncoder::from_isize(1isize);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), add(&zero(), &BigNum::from_u32(1).unwrap()));
        let res = OpenSslAttributeEncoder::from_isize(-1isize);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), sub(&zero(), &BigNum::from_u32(1).unwrap()));
        let res = OpenSslAttributeEncoder::from_isize(std::isize::MAX);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), add(&zero(), &u64_to_bignum(std::isize::MAX as u64)));
        let res = OpenSslAttributeEncoder::from_usize(std::usize::MAX);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), add(&zero(), &u64_to_bignum(std::usize::MAX as u64)));
    }
}
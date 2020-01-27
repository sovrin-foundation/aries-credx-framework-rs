use super::AttributeEncoder;

use amcl_wrapper::field_elem::FieldElement;
use chrono::DateTime;

/// How many bits are used to shift 1 to get to zero centering
pub const BITS_IN_ZERO: usize = 254;

/// Represents an integer than can be cryptographically signed
pub type Attribute = FieldElement;

/// 2^BITS_IN_ZERO. Zero centers numbers used as ECC field elements
/// Should only be used where comparisons are used
fn zero() -> Attribute {
    FieldElement::one().shift_left(BITS_IN_ZERO)
} 

/// Provides various from methods for converting common types to values that can be used for attributes
pub struct FieldElementAttributeEncoder;

/// Provides various from methods for converting common types to values that can be used for attributes
impl AttributeEncoder for FieldElementAttributeEncoder {
    type Output = Attribute;
    /// Takes an date string that is formatted according to RFC3339
    /// and converts it to a Attribute. 
    fn from_rfc3339<'a, A: Into<&'a str>>(value: A) -> Result<Self::Output, String> {
        let dt = DateTime::parse_from_rfc3339(value.into()).map_err(|e| format!("{:?}", e))?;
        let f: Attribute = (dt.timestamp() as u64).into();
        Ok(f + zero())
    }

    /// Takes a floating point number and converts it to a Attribute
    fn from_f64<A: Into<f64>>(value: A) -> Result<Self::Output, String> {
        use std::num::FpCategory::*;
        use num_bigint::Sign::*;

        let value = value.into();

        Ok(
        match value.classify() {
            Nan => Attribute::one(),
            Subnormal => Attribute::from(2),
            Zero => zero(),
            Infinite => {
                if value.is_sign_positive() {
                    let co: amcl_wrapper::types::BigNum = *amcl_wrapper::constants::CurveOrder;
                    Attribute::from(co) - Attribute::from(9)
                } else {
                    Attribute::from(8)
                }
            },
            Normal => {
                let mut b = bigdecimal::BigDecimal::from(value);

                for _ in 0..BITS_IN_ZERO {
                    b = b.double();
                }
                let (bi, _) = b.into_bigint_and_exponent();
                let (sign, bytes) = bi.to_bytes_be();
                let mut data = vec![0u8; amcl_wrapper::constants::FieldElement_SIZE - bytes.len()];
                data.extend_from_slice(&bytes);
                let f = Attribute::from_bytes(data.as_slice()).map_err(|e| format!("{:?}", e))?;
                match sign {
                    NoSign => zero(),
                    Plus => f,
                    Minus => zero() - f
                }
            }
        })
    }

    /// Takes a signed integer and converts it to a Attribute
    fn from_isize<A: Into<isize>>(value: A) -> Result<Self::Output, String> {
        let value = value.into();
        if value < 0 {
            Ok(zero() - Attribute::from(-value as u64))
        } else {
            Ok(zero() + Attribute::from(value as u64))
        }
    }

    /// Takes an unsigned integer and converts it to a Attribute
    fn from_usize<A: Into<usize>>(value: A) -> Result<Self::Output, String> {
        Ok(zero() + Attribute::from(value.into() as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_string_convert() {
        let res = FieldElementAttributeEncoder::from_rfc3339("2018-01-26T18:30:09.453+00:00");
        assert!(res.is_ok());
        assert_eq!(Attribute::from(1_516_991_409u64) + zero() , res.unwrap());

        let res = FieldElementAttributeEncoder::from_rfc3339("2020-01-26T00:30:09.000+18:00");
        assert!(res.is_ok());
        assert_eq!(Attribute::from(1_579_933_809u64) + zero(), res.unwrap());

        let res = FieldElementAttributeEncoder::from_rfc3339("1970-01-01T00:00:00.000+00:00");
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), zero());

        let res = FieldElementAttributeEncoder::from_rfc3339("1900");
        assert!(res.is_err());
    }

    #[test]
    fn decimal_test() {
        let res1 = FieldElementAttributeEncoder::from_f64(1.33f32);
        assert!(res1.is_ok());
        let res2 = FieldElementAttributeEncoder::from_f64(-1.33f32);
        assert!(res2.is_ok());
        assert_eq!(zero(), res1.unwrap() + res2.unwrap());

        let res1 = FieldElementAttributeEncoder::from_f64(std::f64::MAX);
        assert!(res1.is_ok());
        let res2 = res1.unwrap();
        assert_eq!(&res2 - &res2, Attribute::zero());

        let res3 = FieldElementAttributeEncoder::from_f64(std::f64::MIN);
        assert!(res3.is_ok());
        assert_eq!(zero(), res3.unwrap() + res2);

        let res1 = FieldElementAttributeEncoder::from_f64(std::f64::NEG_INFINITY);
        assert!(res1.is_ok());
        assert_eq!(Attribute::from(8), res1.unwrap());

        let co: amcl_wrapper::types::BigNum = *amcl_wrapper::constants::CurveOrder;
        let pos_inf = Attribute::from(co) - Attribute::from(9);
        let res1 = FieldElementAttributeEncoder::from_f64(std::f64::INFINITY);
        assert!(res1.is_ok());
        assert_eq!(pos_inf, res1.unwrap());

        let res1 = FieldElementAttributeEncoder::from_f64(std::f64::NAN);
        assert!(res1.is_ok());
        assert_eq!(Attribute::one(), res1.unwrap());
    }

    #[test]
    fn size_test() {
        let res = FieldElementAttributeEncoder::from_isize(0isize);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), zero());
        let res = FieldElementAttributeEncoder::from_isize(1isize);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), zero() + Attribute::one());
        let res = FieldElementAttributeEncoder::from_isize(-1isize);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), zero() - Attribute::one());
        let res = FieldElementAttributeEncoder::from_isize(std::isize::MAX);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), zero() + Attribute::from(std::isize::MAX as u64));
        let res = FieldElementAttributeEncoder::from_usize(std::usize::MAX);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), zero() + Attribute::from(std::usize::MAX as u64));
    }
}
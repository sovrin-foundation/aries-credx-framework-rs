use amcl_wrapper::field_elem::FieldElement;
use chrono::{DateTime, format::ParseResult};


/// Represents an integer than can be cryptographically signed
pub type Attribute = FieldElement;

/// 2^128. Zero centers numbers used as ECC field elements
fn zero() -> FieldElement {
    FieldElement::one().shift_left(128)
} 


/// Provides various from methods for converting common types to values that can be used for attributes
pub struct AttributeEncoder {

}

/// Provides various from methods for converting common types to values that can be used for attributes
impl AttributeEncoder {
    /// Takes an date string that is formatted according to RFC3339
    /// and converts it to a FieldElement. 
    pub fn from_rfc3339<'a, A: Into<&'a str>>(value: A) -> Result<FieldElement, String> {
        let dt = DateTime::parse_from_rfc3339(value.into()).map_err(|e| format!("{:?}", e))?;
        let f: FieldElement = (dt.timestamp() as u64).into();
        Ok(f + zero())
    }

    /// Takes a floating point number and converts it to a FieldElement
    pub fn from_f64<A: Into<f64>>(value: A) -> Result<FieldElement, String> {
        let mut b = bigdecimal::BigDecimal::from(value.into());
        for _ in 0..128 {
            b = b.double();
        }
        let (bi, _) = b.into_bigint_and_exponent();
        let (sign, bytes) = bi.to_bytes_be();
        let mut data = vec![0u8; amcl_wrapper::constants::FieldElement_SIZE - bytes.len()];
        data.extend_from_slice(&bytes);
        let f = FieldElement::from_bytes(data.as_slice()).map_err(|e| format!("{:?}", e))?;
        Ok(
        match sign {
            num_bigint::Sign::NoSign => zero(),
            num_bigint::Sign::Plus => f + zero(),
            num_bigint::Sign::Minus => zero() - f
        })
    }

    /// Takes a signed integer and converts it to a FieldElement
    pub fn from_isize<A: Into<isize>>(value: A) -> Result<FieldElement, String> {
        let value = value.into();
        if value < 0 {
            Ok(zero() - FieldElement::from(-value as u64))
        } else {
            Ok(zero() + FieldElement::from(value as u64))
        }
    }

    /// Takes an unsigned integer and converts it to a FieldElement
    pub fn from_usize<A: Into<usize>>(value: A) -> Result<FieldElement, String> {
        Ok(zero() + FieldElement::from(value.into() as u64))
    }
}

macro_rules! from_rfc3339_to_unixepoch_impl {
    ($name:ident, $tgt:ident) => {
        impl FromRfc3339ToUnixEpoch<$tgt> for $name {}
    };
}

/// Takes an date string that is formatted according to RFC3339
/// and converts it to a u64. Implementors should convert
/// to an appropriate value that can be cryptographically signed
pub trait FromRfc3339ToUnixEpoch<I: From<u64>> : AsRef<str> {
    /// Take an input and convert it to type `Output`
    fn convert(&self) -> ParseResult<I> {
        let dt = DateTime::parse_from_rfc3339(self.as_ref())?;
        Ok((dt.timestamp() as u64).into())
    }
}
from_rfc3339_to_unixepoch_impl!(String, FieldElement);
from_rfc3339_to_unixepoch_impl!(str, FieldElement);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_string_convert() {
        let res = "2018-01-26T18:30:09.453+00:00".convert();
        assert!(res.is_ok());
        assert_eq!(FieldElement::from(1_516_991_409u64), res.unwrap());

        let res = AttributeEncoder::from_rfc3339("2018-01-26T18:30:09.453+00:00");
        assert!(res.is_ok());
        assert_eq!(FieldElement::from(1_516_991_409u64) + zero() , res.unwrap());

        let res = "2020-01-26T00:30:09.000+18:00".convert();
        assert!(res.is_ok());
        assert_eq!(FieldElement::from(1_579_933_809u64), res.unwrap());

        let res = "1970-01-01T00:00:00.000+00:00".convert();
        assert!(res.is_ok());
        assert!(res.unwrap().is_zero());

        let res = "1900".convert();
        assert!(res.is_err());
    }

    #[test]
    fn decimal_test() {
    }
}
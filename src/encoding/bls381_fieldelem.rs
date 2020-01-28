use super::{AttributeEncoder, BITS_IN_ZERO};

use amcl_wrapper::field_elem::FieldElement;

impl AttributeEncoder for FieldElement {
    type Output = FieldElement;

    fn max() -> Self::Output {
        let co: amcl_wrapper::types::BigNum = *amcl_wrapper::constants::CurveOrder;
        FieldElement::from(co)
    }

    fn zero_center() -> Self::Output {
        FieldElement::one().shift_left(BITS_IN_ZERO)
    }

    fn from_vec(bytes: Vec<u8>) -> Self::Output {
        let mut data = vec![0u8; amcl_wrapper::constants::FieldElement_SIZE - bytes.len()];
        data.extend_from_slice(&bytes); 
        FieldElement::from_bytes(data.as_slice()).map_err(|e| format!("{:?}", e)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_string_convert() {
        let res = FieldElement::encode_from_rfc3339_as_unixtimestamp("2018-01-26T18:30:09.453+00:00");
        assert!(res.is_ok());
        assert_eq!(FieldElement::from(1_516_991_409u64) + FieldElement::zero_center(), res.unwrap());

        let res = FieldElement::encode_from_rfc3339_as_unixtimestamp("2020-01-26T00:30:09.000+18:00");
        assert!(res.is_ok());
        assert_eq!(FieldElement::from(1_579_933_809u64) + FieldElement::zero_center(), res.unwrap());

        let res = FieldElement::encode_from_rfc3339_as_unixtimestamp("1970-01-01T00:00:00.000+00:00");
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), FieldElement::zero_center());

        let res = FieldElement::encode_from_rfc3339_as_unixtimestamp("1900");
        assert!(res.is_err());

        let res = FieldElement::encode_from_rfc3339_as_dayssince1900("1982-12-20T10:45:00.000-06:00");
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), FieldElement::zero_center() + FieldElement::from(30303));
    }

    #[test]
    fn decimal_test() {
        let res1 = FieldElement::encode_from_f64(1.33f32);
        assert!(res1.is_ok());
        let res2 = FieldElement::encode_from_f64(-1.33f32);
        assert!(res2.is_ok());
        assert_eq!(FieldElement::zero_center(), res1.unwrap() + res2.unwrap());

        let res1 = FieldElement::encode_from_f64(std::f64::MAX);
        assert!(res1.is_ok());
        let res2 = res1.unwrap();
        assert_eq!((&res2 - &res2), FieldElement::zero());

        let res3 = FieldElement::encode_from_f64(std::f64::MIN);
        assert!(res3.is_ok());
        assert_eq!(FieldElement::zero_center(), res3.unwrap() + res2);

        let res1 = FieldElement::encode_from_f64(std::f64::NEG_INFINITY);
        assert!(res1.is_ok());
        assert_eq!(FieldElement::from(8), res1.unwrap());

        let co: amcl_wrapper::types::BigNum = *amcl_wrapper::constants::CurveOrder;
        let pos_inf = FieldElement::from(co) - FieldElement::from(9);
        let res1 = FieldElement::encode_from_f64(std::f64::INFINITY);
        assert!(res1.is_ok());
        assert_eq!(pos_inf, res1.unwrap());

        let res1 = FieldElement::encode_from_f64(std::f64::NAN);
        assert!(res1.is_ok());
        assert_eq!(FieldElement::one(), res1.unwrap());
    }

    #[test]
    fn size_test() {
        let res = FieldElement::encode_from_isize(0isize);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), FieldElement::zero_center());
        let res = FieldElement::encode_from_isize(1isize);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), FieldElement::zero_center() + FieldElement::one());
        let res = FieldElement::encode_from_isize(-1isize);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), FieldElement::zero_center() - FieldElement::one());
        let res = FieldElement::encode_from_isize(std::isize::MAX);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), FieldElement::zero_center() + FieldElement::from(std::isize::MAX as u64));
        let res = FieldElement::encode_from_usize(std::usize::MAX);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), FieldElement::zero_center() + FieldElement::from(std::usize::MAX as u64));
    }
}
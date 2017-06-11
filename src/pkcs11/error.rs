use std::result;

use pkcs11::cryptoki::CK_RV;

#[derive(Debug)]
pub struct Pkcs11Error {
  pub description: Option<String>,
  pub rv: Option<CK_RV>
}

pub type Result<T> = result::Result<T, Pkcs11Error>;

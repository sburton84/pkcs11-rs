use std::ptr;

use cryptoki::*;

pub enum Mechanism<'a> {
  Des3Ecb,
  Des3Cbc{iv: &'a [u8]},
  Des3KeyGen
}

impl<'a> Mechanism<'a> {
  pub fn to_ck_mech(&self) -> CK_MECHANISM {
    match *self {
      Mechanism::Des3Ecb => CK_MECHANISM{ mechanism: CKM_DES3_ECB as CK_MECHANISM_TYPE, pParameter: ptr::null_mut(), ulParameterLen: 0 },
      Mechanism::Des3Cbc{iv: _} => CK_MECHANISM{ mechanism: CKM_DES3_CBC as CK_MECHANISM_TYPE, pParameter: ptr::null_mut(), ulParameterLen: 0 },
      Mechanism::Des3KeyGen => CK_MECHANISM{ mechanism: CKM_DES3_KEY_GEN as CK_MECHANISM_TYPE, pParameter: ptr::null_mut(), ulParameterLen: 0 },
    }
  }
}
use cryptoki::*;
use pkcs11::Pkcs11;
use pkcs11::error::*;
use std::ptr;

use pkcs11::slot::session::object::Object;
use pkcs11::slot::session::object::mechanism::Mechanism;

impl<'a> Object<'a> {
  pub fn encrypt(&self, mechanism: Mechanism, data: &mut [u8]) -> Result<Vec<u8>> {
    self.session.slot.pkcs11.encrypt(self, mechanism, data)
  }

  pub fn decrypt(&self, mechanism: Mechanism, ciphertext: &mut [u8]) -> Result<Vec<u8>> {
    self.session.slot.pkcs11.decrypt(self, mechanism, ciphertext)
  }
}

impl Pkcs11 {
  fn encrypt(&self, key: &Object, mechanism: Mechanism, data: &mut [u8]) -> Result<Vec<u8>> {
    try!(self.encrypt_init(key, mechanism));

    let mut cipher_size: CK_ULONG = 0;

    let rv = unsafe {
      (self.function_list.C_Encrypt).unwrap()(key.session.handle, data.as_mut_ptr(), data.len() as CK_ULONG, ptr::null_mut(), &mut cipher_size)
    };

    if rv != CKR_OK as CK_RV {
      return Err(Pkcs11Error{
        description: Some("Error calling C_Encrypt".to_string()),
        rv: Some(rv)
      })
    }

    let mut ciphertext: Vec<u8> = Vec::with_capacity(cipher_size as usize);

    let rv = unsafe {
      (self.function_list.C_Encrypt).unwrap()(key.session.handle, data.as_mut_ptr(), data.len() as CK_ULONG, ciphertext.as_mut_ptr(), &mut cipher_size)
    };

    if rv != CKR_OK as CK_RV {
      return Err(Pkcs11Error{
        description: Some("Error calling C_Encrypt".to_string()),
        rv: Some(rv)
      })
    }

    unsafe {
      ciphertext.set_len(cipher_size as usize);
    }

    Ok(ciphertext)
  }

  fn encrypt_init(&self, key: &Object, mechanism: Mechanism) -> Result<()> {
    let mut ck_mech = mechanism.to_ck_mech();

    let rv = unsafe {
      (self.function_list.C_EncryptInit).unwrap()(key.session.handle, &mut ck_mech as CK_MECHANISM_PTR, key.handle)
    };

    if rv != CKR_OK as CK_RV {
      return Err(Pkcs11Error{
        description: Some("Error calling C_EncryptInit".to_string()),
        rv: Some(rv)
      })
    }

    Ok(())
  }

  fn decrypt(&self, key: &Object, mechanism: Mechanism, ciphertext: &mut [u8]) -> Result<Vec<u8>> {
    try!(self.decrypt_init(key, mechanism));

    let mut plain_size: CK_ULONG = 0;

    let rv = unsafe {
      (self.function_list.C_Decrypt).unwrap()(key.session.handle, ciphertext.as_mut_ptr(), ciphertext.len() as CK_ULONG, ptr::null_mut(), &mut plain_size)
    };

    if rv != CKR_OK as CK_RV {
      return Err(Pkcs11Error{
        description: Some("Error calling C_Decrypt".to_string()),
        rv: Some(rv)
      })
    }

    let mut plaintext: Vec<u8> = Vec::with_capacity(plain_size as usize);

    let rv = unsafe {
      (self.function_list.C_Decrypt).unwrap()(key.session.handle, ciphertext.as_mut_ptr(), ciphertext.len() as CK_ULONG, plaintext.as_mut_ptr(), &mut plain_size)
    };

    if rv != CKR_OK as CK_RV {
      return Err(Pkcs11Error{
        description: Some("Error calling C_Decrypt".to_string()),
        rv: Some(rv)
      })
    }

    unsafe {
      plaintext.set_len(plain_size as usize);
    }

    Ok(plaintext)
  }

  fn decrypt_init(&self, key: &Object, mechanism: Mechanism) -> Result<()> {
    let mut ck_mech = mechanism.to_ck_mech();

    let rv = unsafe {
      (self.function_list.C_DecryptInit).unwrap()(key.session.handle, &mut ck_mech as CK_MECHANISM_PTR, key.handle)
    };

    if rv != CKR_OK as CK_RV {
      return Err(Pkcs11Error{
        description: Some("Error calling C_DecryptInit".to_string()),
        rv: Some(rv)
      })
    }

    Ok(())
  }
}
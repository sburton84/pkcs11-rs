use cryptoki::*;
use pkcs11::Pkcs11;
use pkcs11::error::*;
use pkcs11::slot::session::object::Object;
use pkcs11::slot::session::object::mechanism::Mechanism;

impl<'a> Object<'a> {
  pub fn encrypt(&self, mechanism: Mechanism) -> Result<Vec<u8>> {
    self.session.slot.pkcs11.encrypt(self, mechanism)
  }
}

impl Pkcs11 {
  fn encrypt(&self, key: &Object, mechanism: Mechanism) -> Result<Vec<u8>> {
    self.encrypt_init(key, mechanism);

    Ok(Vec::new())
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
}
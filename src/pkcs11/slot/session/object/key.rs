use cryptoki::*;
use pkcs11::Pkcs11;
use pkcs11::error::*;
use pkcs11::slot::session::Session;
use pkcs11::slot::session::object::Object;
use pkcs11::slot::session::object::attribute::Attribute;
use pkcs11::slot::session::object::mechanism::Mechanism;

impl<'a> Session<'a> {
  pub fn generate_key(&self, mechanism: Mechanism, attributes: &[Attribute]) -> Result<Object> {
    self.slot.pkcs11.generate_key(self, mechanism, attributes)
  }
}

impl Pkcs11 {
  fn generate_key<'a>(&self, session: &'a Session, mechanism: Mechanism, attributes: &[Attribute]) -> Result<Object<'a>> {
    let mut ck_attrs: Vec<CK_ATTRIBUTE> = Vec::new();

    for attribute in attributes {
      ck_attrs.push(attribute.to_ck_attribute());
    }

    let mut object_handle: CK_OBJECT_HANDLE = 0;
    let mut ck_mech = mechanism.to_ck_mech();

    let rv = unsafe {
      (self.function_list.C_GenerateKey).unwrap()(session.handle, &mut ck_mech as CK_MECHANISM_PTR, ck_attrs.as_mut_ptr(), ck_attrs.len() as CK_ULONG, &mut object_handle as CK_OBJECT_HANDLE_PTR)
    };

    if rv != CKR_OK as CK_RV {
      return Err(Pkcs11Error{
        description: Some("Error calling C_GenerateKey".to_string()),
        rv: Some(rv)
      })
    }

    Ok(Object{ session: session, handle: object_handle })
  }
}
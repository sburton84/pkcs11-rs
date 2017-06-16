pub mod attribute;
pub mod key;
pub mod mechanism;
pub mod encrypt;

use std::vec::Vec;

use cryptoki::*;
use pkcs11::Pkcs11;
use pkcs11::error::*;
use pkcs11::slot::session::Session;
use pkcs11::slot::session::object::attribute::Attribute;

const HANDLES_PER_CALL: usize = 10;

pub struct Object<'a> {
  session: &'a Session<'a>,
  handle: CK_OBJECT_HANDLE,
}

impl<'a> Session<'a> {
  pub fn find_objects(&self, attributes: &[Attribute]) -> Result<Vec<Object>> {
    self.slot.pkcs11.find_objects(self, attributes)
  }
}

impl Pkcs11 {
  fn find_objects(&self, session: &Session, attributes: &[Attribute]) -> Result<Vec<Object>> {
    let mut ck_attrs: Vec<CK_ATTRIBUTE> = Vec::new();

    for attribute in attributes {
      ck_attrs.push(attribute.to_ck_attribute());
    }

    let rv = unsafe {
      (self.function_list.C_FindObjectsInit).unwrap()(session.handle, ck_attrs.as_mut_ptr(), ck_attrs.len() as CK_ULONG)
    };

    if rv != CKR_OK as CK_RV {
      return Err(Pkcs11Error{
        description: Some("Error calling C_FindObjectsInit".to_string()),
        rv: Some(rv)
      })
    }

    let mut objects: Vec<Object> = Vec::new();

    let mut object_count: CK_ULONG = 0;
    let mut object_handles: Vec<CK_OBJECT_HANDLE> = Vec::with_capacity(HANDLES_PER_CALL);

    let rv = unsafe {
      (self.function_list.C_FindObjects).unwrap()(session.handle, object_handles.as_mut_ptr(), object_handles.len() as CK_ULONG, &mut object_count as CK_ULONG_PTR)
    };

    let rv = unsafe {
      (self.function_list.C_FindObjectsFinal).unwrap()(session.handle)
    };

    if rv != CKR_OK as CK_RV {
      return Err(Pkcs11Error{
        description: Some("Error calling C_FindObjectsFinal".to_string()),
        rv: Some(rv)
      })
    }

    Ok(objects)
  }
}
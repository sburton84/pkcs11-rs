use std::ptr;

use cryptoki::*;
use pkcs11::error::*;
use pkcs11::slot::Slot;
use pkcs11::Pkcs11;

pub struct Session<'a> {
  slot: &'a Slot<'a>,
  handle: CK_SESSION_HANDLE,
}

impl<'a> Drop for Session<'a> {
  fn drop(&mut self) {
    self.close_session();
  }
}

impl<'a> Slot<'a> {
  pub fn open_session(&self) -> Result<Session> {
    self.pkcs11.open_session(self)
  }
}

impl<'a> Session<'a> {
  pub fn close_session(&self) -> Result<()> {
    self.slot.pkcs11.close_session(self.handle)
  }
}

impl Pkcs11 {
  pub fn open_session<'a, 'b>(&'a self, slot: &'b Slot) -> Result<Session<'b>> {
    let mut session_handle: CK_SESSION_HANDLE = 0;

    let rv = unsafe {
      (self.function_list.C_OpenSession).unwrap()(slot.id, CKF_SERIAL_SESSION as CK_FLAGS, ptr::null_mut(), None, &mut session_handle as CK_SESSION_HANDLE_PTR)
    };

    if rv != CKR_OK as CK_RV {
      return Err(Pkcs11Error{
        description: Some("Error calling C_OpenSession".to_string()),
        rv: Some(rv)
      })
    }

    Ok(Session { slot: slot, handle: session_handle })
  }

  fn close_session(&self, session_handle: CK_SESSION_HANDLE) -> Result<()> {
    let rv = unsafe {
      (self.function_list.C_CloseSession).unwrap()(session_handle)
    };

    if rv != CKR_OK as CK_RV {
      return Err(Pkcs11Error{
        description: Some("Error calling C_CloseSession".to_string()),
        rv: Some(rv)
      })
    }

    Ok(())
  }
}
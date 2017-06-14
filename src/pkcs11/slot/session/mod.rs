pub mod object;

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

  pub fn log_in(&self, pin: &str) -> Result<()> {
    self.slot.pkcs11.log_in(self.handle, pin.to_string().as_mut_str())
  }

  pub fn log_out(&self) -> Result<()> {
    self.slot.pkcs11.log_out(self.handle)
  }
}

impl Pkcs11 {
  fn open_session<'a, 'b>(&'a self, slot: &'b Slot) -> Result<Session<'b>> {
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

  fn log_in(&self, session_handle: CK_SESSION_HANDLE, pin: &mut str) -> Result<()> {
    let rv = unsafe {
      (self.function_list.C_Login).unwrap()(session_handle, CKU_USER as CK_USER_TYPE, pin as *mut _ as CK_UTF8CHAR_PTR, pin.len() as CK_ULONG)
    };

    if rv != CKR_OK as CK_RV {
      return Err(Pkcs11Error{
        description: Some("Error calling C_Login".to_string()),
        rv: Some(rv)
      })
    }

    Ok(())
  }

  fn log_out(&self, session_handle: CK_SESSION_HANDLE) -> Result<()> {
    let rv = unsafe {
      (self.function_list.C_Logout).unwrap()(session_handle)
    };

    if rv != CKR_OK as CK_RV {
      return Err(Pkcs11Error{
        description: Some("Error calling C_Logout".to_string()),
        rv: Some(rv)
      })
    }

    Ok(())
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
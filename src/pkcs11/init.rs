use std::ptr;

use libloading;

use pkcs11::error::*;
use pkcs11::cryptoki::*;
use pkcs11::Pkcs11;

impl Pkcs11 {
  pub fn get_function_list(lib: &libloading::Library) -> Result<CK_FUNCTION_LIST> {
    unsafe {
      let mut function_list_ptr: CK_FUNCTION_LIST_PTR = ptr::null_mut();

      let func_ptr: libloading::Symbol<unsafe extern fn(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV> = lib.get(b"C_GetFunctionList").expect("Error getting C_GetFunctionList function pointer");
      let rv = func_ptr(&mut function_list_ptr as CK_FUNCTION_LIST_PTR_PTR);

      if rv != CKR_OK as CK_RV {
        return Err(Pkcs11Error{
          description: Some("Error calling C_GetFunctionList".to_string()),
          rv: Some(rv)
        })
      }

      Ok(*function_list_ptr)
    }
  }

  pub fn initialize(&mut self) -> Result<()> {
    let mut init = self.initialized.lock().unwrap();

    if !*init {
      let mut args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: CKF_OS_LOCKING_OK as CK_FLAGS,
        pReserved: ptr::null_mut(),
      };

      let rv = unsafe {
        (self.function_list.C_Initialize).unwrap()(&mut args as *mut _ as CK_VOID_PTR)
      };

      if rv != CKR_OK as CK_RV {
        return Err(Pkcs11Error{
          description: Some("Error calling C_Initialize".to_string()),
          rv: Some(rv)
        })
      }

      *init = true;
    }

    Ok(())
  }

  pub fn finalize(&mut self) -> Result<()> {
    let mut init = self.initialized.lock().unwrap();

    if *init {
      let rv = unsafe {
        (self.function_list.C_Finalize).unwrap()(ptr::null_mut())
      };

      if rv != CKR_OK as CK_RV {
        return Err(Pkcs11Error{
          description: Some("Error calling C_Finalize".to_string()),
          rv: Some(rv)
        })
      }

      *init = false;
    }

    Ok(())
  }
}
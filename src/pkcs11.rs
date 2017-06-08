use std::os;
use std::ptr;
use std::error::Error;

use libloading;

use cryptoki::*;
use error::*;

pub struct Pkcs11 {
  lib: libloading::Library,
  function_list: CK_FUNCTION_LIST,
  initialized: bool
}

impl Drop for Pkcs11 {
  fn drop(&mut self) {
    self.finalize();
  }
}

impl Pkcs11 {
  pub fn new(lib_path: &str) -> Result<Pkcs11> {
    let lib = try!(Pkcs11::load_lib(lib_path));
    let function_list = try!(Pkcs11::get_function_list(&lib));

    let mut ctx = Pkcs11 {
      lib: lib,
      function_list: function_list,
      initialized: false
    };

    ctx.initialize();

    Ok(ctx)
  }

  fn load_lib(lib_path: &str) -> Result<libloading::Library> {
    let lib = match libloading::Library::new(lib_path) {
      Ok(l) => l,
      Err(e) => return Err(Pkcs11Error { 
        description: Some(e.description().to_string()),
        rv: None
      }),
    };

    Ok(lib)
  }

  fn get_function_list(lib: &libloading::Library) -> Result<CK_FUNCTION_LIST> {
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

  fn initialize(&mut self) -> Result<()> {
    if !self.initialized {
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

      self.initialized = true;
      Ok(())
    } else {
      panic!("Attempt to initialize PKCS#11 library already initialized");
    }
  }

  fn finalize(&mut self) -> Result<()> {
    if self.initialized {
      let rv = unsafe {
        (self.function_list.C_Finalize).unwrap()(ptr::null_mut())
      };

      if rv != CKR_OK as CK_RV {
        return Err(Pkcs11Error{
          description: Some("Error calling C_Finalize".to_string()),
          rv: Some(rv)
        })
      }

      self.initialized = false;
      Ok(())
    } else {
      panic!("Attempt to finalize uninitialized PKCS#11 library");
    }
  }

  fn get_slot_list(&self) {
    unsafe {
      //(self.function_list.C_GetSlotList).unwrap()();
    }
  }
}

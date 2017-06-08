use std::os;
use std::ptr;

use libloading;

use cryptoki::*;
use funclist::*;

pub struct Context {
  lib: libloading::Library,
  function_list: CK_FUNCTION_LIST,
  initialized: bool
}

impl Drop for Context {
  fn drop(&mut self) {
    self.finalize();
  }
}

impl Context {
  pub fn new(lib_path: &str) -> Context {
    let lib = load_lib(lib_path);
    let function_list = get_function_list(&lib);

    let mut ctx = Context {
      lib: lib,
      function_list: function_list,
      initialized: false
    };

    ctx.initialize();

    ctx
  }

  fn initialize(&mut self) {
    if !self.initialized {
      let mut args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: CKF_OS_LOCKING_OK as CK_FLAGS,
        pReserved: ptr::null_mut(),
      };

      unsafe {
        (self.function_list.C_Initialize).unwrap()(&mut args as *mut _ as *mut os::raw::c_void);
      }

      self.initialized = true;
    } else {
      panic!("Attempt to initialize PKCS#11 library already initialized");
    }
  }

  fn finalize(&mut self) {
    if self.initialized {
      unsafe {
        (self.function_list.C_Finalize).unwrap()(ptr::null_mut());
      }

      self.initialized = false;
    } else {
      panic!("Attempt to finalize uninitialized PKCS#11 library");
    }
  }
}

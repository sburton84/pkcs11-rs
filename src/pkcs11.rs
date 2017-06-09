use std::os;
use std::ptr;
use std::path::Path;
use std::error::Error;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::Arc;

use libloading;

use cryptoki::*;
use error::*;

pub struct Pkcs11 {
  lib: libloading::Library,
  function_list: CK_FUNCTION_LIST,
  initialized: bool
}

lazy_static! {
    static ref registry: Mutex<HashMap<String, Arc<Mutex<Pkcs11>>>> = {
        let mut m = HashMap::new();
        Mutex::new(m)
    };
}

impl Drop for Pkcs11 {
  fn drop(&mut self) {
    if self.initialized {
      self.finalize();
    }
  }
}

impl Pkcs11 {
  pub fn new(lib_path: &str) -> Result<Arc<Mutex<Pkcs11>>> {
    let path = try!(Pkcs11::canonicalize_path(lib_path));
    let p11 = try!(Pkcs11::get_or_create(&path));

    Ok(p11)
  }

  fn canonicalize_path(lib_path: &str) -> Result<String> {
    // Canonicalize path
    let path = match Path::new(lib_path).canonicalize() {
      Ok(path) => path,
      Err(e) => return Err(Pkcs11Error { 
        description: Some(e.description().to_string()),
        rv: None
      }),
    }.to_string_lossy().into_owned(); 

    Ok(path)
  }

  fn get_or_create(path: &str) -> Result<Arc<Mutex<Pkcs11>>> {
    let mut p11;

    let mut reg = registry.lock().unwrap();

    if reg.contains_key(path) {
      p11 = reg.get_mut(path).unwrap().clone();

      if !p11.lock().unwrap().initialized {
        p11.lock().unwrap().initialize();
      }
    } else {
      let new_p11 = try!(Pkcs11::init_lib(path));

      reg.insert(path.to_string(), Arc::new(Mutex::new(new_p11)));

      p11 = reg.get_mut(path).unwrap().clone();
    }

    Ok(p11)
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

  fn init_lib(lib_path: &str) -> Result<Pkcs11> {
    let lib = try!(Pkcs11::load_lib(lib_path));
    let function_list = try!(Pkcs11::get_function_list(&lib));

    let mut p11 = Pkcs11 {
      lib: lib,
      function_list: function_list,
      initialized: false
    };

    p11.initialize();

    Ok(p11)
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

  pub fn get_slot_list(&self, token_present: bool) {
    let mut slot_count: u64 = 0;

    unsafe {
      (self.function_list.C_GetSlotList).unwrap()(token_present as CK_BBOOL, ptr::null_mut(), &mut slot_count as CK_ULONG_PTR);
    }
  }
}

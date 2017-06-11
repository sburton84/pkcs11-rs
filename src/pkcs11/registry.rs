use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::Arc;
use std::path::Path;
use std::error::Error;

use libloading;

use pkcs11::error::*;
use pkcs11::Pkcs11;

lazy_static! {
    static ref REGISTRY: Mutex<HashMap<String, Arc<Pkcs11>>> = {
        let mut m = HashMap::new();
        Mutex::new(m)
    };
}

pub fn get_entry(lib_path: &str) -> Result<Arc<Pkcs11>> {
  let path = try!(canonicalize_path(lib_path));
  let p11 = try!(get_or_create(&path));

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

fn get_or_create(path: &str) ->  Result<Arc<Pkcs11>>  {
  let mut p11;

  let mut reg = REGISTRY.lock().unwrap();

  if reg.contains_key(path) {
    p11 = reg.get_mut(path).unwrap().clone();
  } else {
    let new_p11 = try!(init_lib(path));

    reg.insert(path.to_string(), Arc::new(new_p11));

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
  let lib = try!(load_lib(lib_path));
  let function_list = try!(Pkcs11::get_function_list(&lib));

  let mut p11 = Pkcs11 {
    lib: lib,
    function_list: function_list,
    initialized: Mutex::new(false)
  };

  try!(p11.initialize());

  Ok(p11)
}
use libloading;

use cryptoki::*;
use funclist::*;

pub struct Context {
  lib: libloading::Library,
  function_list: CK_FUNCTION_LIST
}

impl Context {
  pub fn new(lib_path: &str) -> Context {
    let lib = load_lib(lib_path);
    let function_list = get_function_list(&lib);

    Context {
      lib: lib,
      function_list: function_list
    }
  }
}

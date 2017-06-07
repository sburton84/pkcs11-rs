use cryptoki::*;

pub struct Context {
  lib: &str,
  function_list: CK_FUNCTION_LIST
}

impl Context {
  pub fn new(lib: &str) {
    Context { lib: lib }
  }
}

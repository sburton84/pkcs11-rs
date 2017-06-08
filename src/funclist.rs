use std::ptr;

use libloading;

use cryptoki::*;

pub fn load_lib(lib_path: &str) -> libloading::Library {
  libloading::Library::new(lib_path).expect("Error loading PKCS#11 library")
}

pub fn get_function_list(lib: &libloading::Library) -> CK_FUNCTION_LIST {
  let function_list: CK_FUNCTION_LIST;
  
  unsafe {
    let mut function_list_ptr: CK_FUNCTION_LIST_PTR = ptr::null_mut();

    let get_function_list: libloading::Symbol<unsafe extern fn(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV> = lib.get(b"C_GetFunctionList").expect("Error getting C_GetFunctionList function pointer");
    get_function_list(&mut function_list_ptr as CK_FUNCTION_LIST_PTR_PTR);

    function_list = *function_list_ptr;
  }

  function_list
}
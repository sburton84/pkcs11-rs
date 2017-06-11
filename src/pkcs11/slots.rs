use std::ptr;

use pkcs11::cryptoki::*;
use pkcs11::Pkcs11;

impl Pkcs11 {
  pub fn get_slot_list(&self, token_present: bool) {
    let mut slot_count: u64 = 0;

    unsafe {
      (self.function_list.C_GetSlotList).unwrap()(token_present as CK_BBOOL, ptr::null_mut(), &mut slot_count as CK_ULONG_PTR);
    }
  }
}

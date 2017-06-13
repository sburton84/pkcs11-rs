use std::ptr;
use std::vec::Vec;
use std::mem;

use pkcs11::error::*;
use pkcs11::cryptoki::*;
use pkcs11::Pkcs11;

pub struct Slot<'pkcs11> {
  pkcs11: &'pkcs11 Pkcs11,
  id: CK_SLOT_ID,
}

pub struct SlotInfo {
  pub description: String
}

impl<'pkcs11> Slot<'pkcs11> {
  pub fn get_slot_info(&self) -> Result<SlotInfo> {
    self.pkcs11.get_slot_info(self.id)
  }
}

impl Pkcs11 {
  pub fn get_slot_list(&self, token_present: bool) -> Result<Vec<Slot>> {
    let mut slot_count: u64 = 0;

    let rv = unsafe {
      (self.function_list.C_GetSlotList).unwrap()(token_present as CK_BBOOL, ptr::null_mut(), &mut slot_count as CK_ULONG_PTR)
    };

    if rv != CKR_OK as CK_RV {
      return Err(Pkcs11Error{
        description: Some("Error calling C_Initialize".to_string()),
        rv: Some(rv)
      })
    }

    let mut slot_ids: Vec<u64> = Vec::with_capacity(slot_count as usize);

    if slot_count > 0 {
      let rv = unsafe {
        (self.function_list.C_GetSlotList).unwrap()(token_present as CK_BBOOL, slot_ids.as_mut_ptr(), &mut slot_count as CK_ULONG_PTR)
      };

      if rv != CKR_OK as CK_RV {
        return Err(Pkcs11Error{
          description: Some("Error calling C_Initialize".to_string()),
          rv: Some(rv)
        })
      }

      unsafe {
        slot_ids.set_len(slot_count as usize);
      }
    }

    let mut slots: Vec<Slot> = Vec::with_capacity(slot_count as usize);

    for slot_id in slot_ids {
      slots.push(Slot{ pkcs11: self, id: slot_id });
    }

    Ok(slots)
  }

  fn get_slot_info(&self, slot_id: u64) -> Result<SlotInfo> {
    let mut slot_info: CK_SLOT_INFO;

    let rv = unsafe {
      slot_info = mem::zeroed();
      (self.function_list.C_GetSlotInfo).unwrap()(slot_id, &mut slot_info as CK_SLOT_INFO_PTR)
    };

    if rv != CKR_OK as CK_RV {
      return Err(Pkcs11Error{
        description: Some("Error calling C_GetSlotInfo".to_string()),
        rv: Some(rv)
      })
    }

    Ok(SlotInfo{ description: String::from_utf8(slot_info.slotDescription.to_vec()).unwrap() })
  }
}

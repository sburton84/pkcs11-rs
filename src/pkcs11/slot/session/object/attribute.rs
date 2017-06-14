use std::mem;

use cryptoki::*;

pub enum Class {
  PublicKey,
  PrivateKey
}

pub enum Attribute<'a> {
  Class(Class),
  Token(bool),
  Private(bool),
  Label(&'a str)
}

impl<'a> Attribute<'a> {
  pub fn to_ck_attribute(&self) -> CK_ATTRIBUTE {
    match *self {
      Attribute::Class(ref c) => match *c {
        Class::PublicKey => CK_ATTRIBUTE{ type_: CKA_CLASS as CK_ATTRIBUTE_TYPE, pValue: &mut CKO_PUBLIC_KEY as *mut _ as CK_VOID_PTR, ulValueLen: mem::size_of::<::std::os::raw::c_uint>() as CK_ULONG },
        Class::PrivateKey => CK_ATTRIBUTE{ type_: CKA_CLASS as CK_ATTRIBUTE_TYPE, pValue: &mut CKO_PRIVATE_KEY as *mut _ as CK_VOID_PTR, ulValueLen: mem::size_of::<::std::os::raw::c_uint>() as CK_ULONG },
      },
      Attribute::Token(mut b) => CK_ATTRIBUTE{ type_: CKA_TOKEN as CK_ATTRIBUTE_TYPE, pValue: &mut b as *mut _ as CK_VOID_PTR, ulValueLen: mem::size_of::<bool>() as CK_ULONG },
      Attribute::Private(mut b) => CK_ATTRIBUTE{ type_: CKA_PRIVATE as CK_ATTRIBUTE_TYPE, pValue: &mut b as *mut _ as CK_VOID_PTR, ulValueLen: mem::size_of::<bool>() as CK_ULONG },
      Attribute::Label(ref s) => CK_ATTRIBUTE{ type_: CKA_LABEL as CK_ATTRIBUTE_TYPE, pValue: s.as_ptr() as CK_VOID_PTR, ulValueLen: s.len() as CK_ULONG },
    }
  }
}
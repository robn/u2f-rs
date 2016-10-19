extern crate serde;
extern crate serde_json;

include!(concat!(env!("OUT_DIR"), "/serde_types.rs"));

extern crate ring;
extern crate webpki;
extern crate untrusted;
extern crate base64;
extern crate hex_slice; // XXX REMOVE

#[macro_use] extern crate error_chain;

pub mod challenge;
pub mod registration;

pub use self::challenge::challenge;

use serde_types::registration::*;
use serde_json;

use base64;
use base64::Base64Mode;

use webpki::EndEntityCert;
use untrusted::Input;

use hex_slice::AsHex; // XXX REMOVE

use std::str;
use std::io::Read;

pub struct Registration {
  challenge:         String,
  app_id:            String,
  origin:            String,
  registration_data: String,
  client_data:       String,
}

pub struct Key {
  handle: String,
  data:   String,
}

error_chain! {
  types {
    Error, ErrorKind, ChainErr, Result;
  }

  errors {
    ClientDataDecodeFailed {
      description("client data decode failed")
    }
    ClientDataParseFailed {
      description("client data parse failed")
    }
    InvalidClientDataChallenge {
      description("invalid client data (challenge doesn't match)")
    }
    InvalidClientDataOrigin {
      description("invalid client data (origin doesn't match)")
    }

    RegistrationDataDecodeFailed {
      description("registration data decode failed")
    }
    RegistrationDataParseFailed {
      description("registration data parse failed")
    }
  }
}

pub fn verify(registration: &Registration) -> Result<Key> {
  let client_data = try!(extract_client_data(&registration.client_data));

  if registration.challenge != client_data.challenge {
    return Err(ErrorKind::InvalidClientDataChallenge.into());
  }
  if registration.origin != client_data.origin {
    return Err(ErrorKind::InvalidClientDataOrigin.into());
  }

  let registration_data = try!(extract_registration_data(&registration.registration_data));

  Ok(Key { handle: String::from(""), data: String::from("") })
}

fn extract_client_data(client_data: &String) -> Result<ClientData> {
  let bytes = try!(
    base64::decode_mode(client_data, Base64Mode::UrlSafe)
      .chain_err(|| ErrorKind::ClientDataDecodeFailed)
  );
  let json = try!(
    str::from_utf8(&bytes).
      chain_err(|| ErrorKind::ClientDataDecodeFailed)
  );

  let client_data = try!(
    serde_json::from_str(json)
      .chain_err(|| ErrorKind::ClientDataParseFailed)
  );

  Ok(client_data)
}

struct RegistrationData { }

fn extract_registration_data(registration_data: &String) -> Result<RegistrationData> {
  let bytes = try!(
    base64::decode_mode(registration_data, Base64Mode::UrlSafe)
      .chain_err(|| ErrorKind::RegistrationDataDecodeFailed)
  );
  let mut slice: &[u8] = &bytes[..];

  let reserved = {
    let mut buf: [u8; 1] = [0; 1];
    try!(slice.read_exact(&mut buf[..])
      .chain_err(|| ErrorKind::RegistrationDataParseFailed));
    buf
  };
  println!("reserved {:x}", reserved.as_hex());

  // XXX test reserved == 0x05

  let public_key = {
    let mut buf: [u8; 65] = [0; 65];
    try!(slice.read_exact(&mut buf[..])
      .chain_err(|| ErrorKind::RegistrationDataParseFailed));
    buf
  };
  println!("public_key {:x}", public_key.as_hex());

  let key_handle_length: usize = {
    let mut buf: [u8; 1] = [0; 1];
    try!(slice.read_exact(&mut buf[..])
      .chain_err(|| ErrorKind::RegistrationDataParseFailed));
    buf[0] as usize
  };
  println!("key_handle_length {:x}", key_handle_length);

  let key_handle = {
    let mut buf = vec![0; key_handle_length].into_boxed_slice();
    try!(slice.read_exact(&mut buf[..])
      .chain_err(|| ErrorKind::RegistrationDataParseFailed));
    buf
  };
  println!("key_handle {:x}", key_handle.as_hex());

  let (cert_der, sig) = {
    let mut buf = vec![];
    try!(slice.read_to_end(&mut buf)
      .chain_err(|| ErrorKind::RegistrationDataParseFailed));

    let cert_len: usize = (((buf[2] as u16) << 8) | (buf[3] as u16)) as usize;

    let (left, right) = buf.split_at_mut(cert_len+4);
    (left.to_vec(), right.to_vec())
  };

  println!("cert_der {:x}", cert_der.as_hex());
  println!("sig {:x}", sig.as_hex());

  /*
  let cert = try!(EndEntityCert::from(Input::from(cert_der.as_slice()))
                .chain_err(|| ErrorKind::RegistrationDataParseFailed));
  println!("{:?}", cert);
  */

  let cert = EndEntityCert::from(Input::from(cert_der.as_slice())).unwrap();
  //println!("{:?}", cert);


/*
  let cert_type: usize = {
    let mut buf: [u8; 2] = [0; 2];
    try!(slice.read_exact(&mut buf[..])
      .chain_err(|| ErrorKind::RegistrationDataParseFailed));
    (((buf[0] as u16) << 8) | (buf[1] as u16)) as usize
  };
  println!("cert_type {:x}", cert_type);

  let cert_len: usize = {
    let mut buf: [u8; 2] = [0; 2];
    try!(slice.read_exact(&mut buf[..])
      .chain_err(|| ErrorKind::RegistrationDataParseFailed));
    (((buf[0] as u16) << 8) | (buf[1] as u16)) as usize
  };
  println!("cert_len {:x}", cert_len);

  let cert_raw = {
    let mut buf = vec![0; cert_len].into_boxed_slice();
    try!(slice.read_exact(&mut buf[..])
      .chain_err(|| ErrorKind::RegistrationDataParseFailed));
    buf
  };
  println!("cert_raw {:x}", cert_raw.as_hex());

  let sig = {
    let mut buf = vec![];
    try!(slice.read_to_end(&mut buf)
      .chain_err(|| ErrorKind::RegistrationDataParseFailed));
    buf
  };
  println!("sig {:x}", sig.as_hex());
*/

  Ok(RegistrationData { })
}

#[cfg(test)]
mod tests {
  use serde_types::registration::*;

  #[test]
  fn extract_client_data() {
    let encoded = "eyAiY2hhbGxlbmdlIjogIjl6UkpvTmJvS0hCWjJBcVBST3U0cndQd0gwVzN5SUtnTW5FUV9yekxVMjgiLCAib3JpZ2luIjogImh0dHBzOlwvXC9leGFtcGxlLmNvbSIsICJ0eXAiOiAibmF2aWdhdG9yLmlkLmZpbmlzaEVucm9sbG1lbnQiIH0";
    assert_eq!(
      super::extract_client_data(&String::from(encoded)).unwrap(),
      ClientData {
        challenge: String::from("9zRJoNboKHBZ2AqPROu4rwPwH0W3yIKgMnEQ_rzLU28"),
        origin:    String::from("https://example.com"),
        typ:       String::from("navigator.id.finishEnrollment"),
      });
  }

  #[test]
  fn extract_registration_data() {
    let encoded = "BQSmbdaT8K7iPmOzqW6nXt3cvwTV0w-KOtQDoYtQOZBbb1kUj6BHtCQHd2iAzsIZ778lUL4Ai4uZ5QirctGyBQrMQE4E7rFBanDGRnmnF1FSYtvw6wmOXtu2HeXQwNB00vIYKSHgev-8vRkQm6MHVkl0tLYOe_yd5YqbIFJybydqYm4wggGqMIIBUaADAgECAgkA_lb-euH_GA4wCgYIKoZIzj0EAwIwMjEwMC4GA1UEAwwnUGx1Zy11cCBGSURPIEludGVybmFsIEF0dGVzdGF0aW9uIENBICMxMB4XDTE0MTAwMzA4MDY0OFoXDTM0MTAwMzA4MDY0OFowQDE-MDwGA1UEAww1UGx1Zy11cCBGSURPIFByb2R1Y3Rpb24gQXR0ZXN0YXRpb24gI2ZlNTZmZTdhZTFmZjE4MGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR16gZg4pBjdIQ3AACvqjIlPoJ72Eh0k6aGpWhMZcrOCYvov0uHJT3vlrlAIwEG_EYGH31lRsFvFLJavzAZ2PQno0IwQDAdBgNVHQ4EFgQUditEb_KU7TIq5CkJT6mE2IU-NYAwHwYDVR0jBBgwFoAUz6dE8qFiUPA56ZKF49pQ532wOqgwCgYIKoZIzj0EAwIDRwAwRAIga1_qf93OZYQ7Jdam_IpNtzuAseZELqsGd6k-Pbk1HyICIFlbgjJ5IcKPrSBiuSrqB8Q3pU1GpiyL5u77aVuKsUQWMEQCIHjpF88WLKYQMZNsv2NoCOquWUiZH4zAHMiSE9R-QM6EAiADA24B1IVEyvbEMDR0xwhOStX0URFKBIeV7VU-d8rT5g";
    super::extract_registration_data(&String::from(encoded)).unwrap();
  }
}

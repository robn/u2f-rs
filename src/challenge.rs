use ring::rand::SystemRandom;
use base64;
use base64::Base64Mode;

pub fn challenge() -> String {
  let mut buf: [u8; 32] = [0; 32];
  let r = SystemRandom::new();
  r.fill(&mut buf).ok(); // XXX panic, but nicer?
  base64::encode_mode(&buf, Base64Mode::UrlSafe)
}

#[cfg(test)]
mod tests {
  #[test]
  fn challenge() {
    assert_eq!(super::challenge().len(), 44);
  }
}

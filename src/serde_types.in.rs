mod serde_types {

  pub mod registration {

    #[derive(Serialize,Deserialize,Clone,PartialEq,Debug)]
    pub struct ClientData {
      pub challenge: String,
      pub origin:    String,
      pub typ:       String,
    }

  }

}

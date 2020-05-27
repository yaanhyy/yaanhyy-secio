#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Propose {
    #[prost(bytes, optional, tag="1")]
    pub rand: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(bytes, optional, tag="2")]
    pub pubkey: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(string, optional, tag="3")]
    pub exchanges: ::std::option::Option<std::string::String>,
    #[prost(string, optional, tag="4")]
    pub ciphers: ::std::option::Option<std::string::String>,
    #[prost(string, optional, tag="5")]
    pub hashes: ::std::option::Option<std::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Exchange {
    #[prost(bytes, optional, tag="1")]
    pub epubkey: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(bytes, optional, tag="2")]
    pub signature: ::std::option::Option<std::vec::Vec<u8>>,
}

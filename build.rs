extern crate protoc_grpcio;

use std::path::Path;

//fn main() {
//    let proto_root = Path::new("src");
//    println!("cargo:rerun-if-changed={}", proto_root.display());
//    protoc_grpcio::compile_grpc_protos(&["structs.proto"], &[proto_root], &proto_root, None)
//        .expect("Failed to compile gRPC definitions!");
////    protoc_grpcio::compile_grpc_protos(&["keys.proto"], &[proto_root], &proto_root, None)
////        .expect("Failed to compile gRPC definitions!");
//}


fn main() {
    prost_build::compile_protos(&["src/structs.proto"], &["src"]).unwrap();
    prost_build::compile_protos(&["src/keys.proto"], &["src"]).unwrap();
}

use nsm_io::Request;
use serde_bytes::ByteBuf;

fn main() {
    // Initialize NSM driver
    let nsm_fd = nsm_driver::nsm_init();

    // Prepare public key and user data
    let public_key = ByteBuf::from("my super secret key");
    let hello = ByteBuf::from("hello, world!");

    // Create an attestation request
    let request = Request::Attestation {
        public_key: Some(public_key),
        user_data: Some(hello),
        nonce: None,
    };

    // Process the attestation request using the NSM driver
    let response = nsm_driver::nsm_process_request(nsm_fd, request);
    
    // Print the response (attestation document)
    println!("{:?}", response);

    // Exit and cleanup NSM
    nsm_driver::nsm_exit(nsm_fd);
}

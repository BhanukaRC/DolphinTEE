# Implementation of Secure Communication in Dolphin: Integrating Trusted Execution Environments for Enhanced Caller Privacy (thesis project)

## Acknowledgments

These three GitHub repositories and the medium article were reffered when building this project:

1. [AWS Nitro Enclaves Samples](https://github.com/aws/aws-nitro-enclaves-samples/tree/main/vsock_sample/py)
    - This repository offered practical examples of using vsock for communication with Nitro Enclaves.
    - The sample code for vsock communication and enclave setup was instrumental in shaping the communication logic used in this project.
2. [TLS Client Handshake in Pure Python by Neal Yip](https://github.com/nealyip/tls_client_handshake_pure_python):  
    - This repository provided an in-depth example of implementing a TLS client handshake in pure Python. 
    - This kind of a solution was very much needed to manage the confidential communication between the Enclave and the ublic communication server (ex: Gmail) via an untrusted parent application in the EC2.
3. [Nitro Enclave Python Demo by Richard Fan](https://github.com/richardfan1126/nitro-enclave-python-demo/tree/master/attestation_verifier?source=post_page-----7824e176ffa4--------------------------------):
    - This repository provided a foundational understanding of the attestation verification process in Nitro Enclaves.
    - Key concepts and implementation details for the attestation verifier were adapted from this source.
4. [Privacy Preserving Deep Learning with AWS Nitro Enclaves by Evan Diewald](https://towardsdatascience.com/privacy-preserving-deep-learning-with-aws-nitro-enclaves-74c72a17f857):
    - Provided the basic understanding of the AWS Nitro Enclaves.

I extend my gratitude to the contributors of these projects and articles for their valuable work.
# Enclave Instance

## Overview

The project mainly demonstrates the programme the callee of Dolphin should run in the nitros enclave of an EC2. It would be communicating with the parent instance via a local socket. This programme orchestrates the TLS connection the parent instance would be making with the Email server (ex: AWS SES).

## Files Description for Main Files

- **server_aws.py**: The enclave-running application.

Most of the other files are used for orchestrating the TLS handshake. 

## Setting up the Enclave  

1. When spinning up an EC2, go to advanced settings and select AWS Nitro Enclave mode. Choose Amazon Linux as the OS.
2. Install Necessary Packages:
    - sudo yum update -y
    - sudo yum install -y aws-nitro-enclaves-cli
    - sudo service docker start
    - sudo usermod -aG ne ec2-user && sudo usermod -aG docker ec2-user
    - sudo vim /etc/nitro_enclaves/allocator.yaml  # Set memory allocation, e.g., 1024 * 2

3. Reboot the Instance.
4. Start Nitro Enclaves Allocator Service:  
    - sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service
    - sudo yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
5. Build and Run the Enclave:
    - docker build -t server -f Dockerfile .
    - nitro-cli build-enclave --docker-uri server --output-file server.eif
6. Copy the PCR2 value and use it to replace the hardcoded PCR2 value in the local_setup/ws_local_client.py

## Running the application

1. Normal mode:
    - nitro-cli run-enclave --eif-path server.eif --cpu-count 2 --memory 1024 --enclave-cid 10000
2. If debugging is the purpose, run on debug mode with console logs. But the attestation would fail since the PCR values would be resetted to all zeros on debugging mode:
    - nitro-cli run-enclave --eif-path server.eif --cpu-count 2 --memory 1024 --enclave-cid 10000 --debug-mode --attach-console

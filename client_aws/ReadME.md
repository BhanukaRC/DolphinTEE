# Parent Instance

## Overview

The project mainly demonstrates the programme the callee of Dolphin should run in an EC2. It should make a web socket connection with the local instance and forward the instructions coming from the the local instance to the Enclave-running code. The programme also initiates a TLS handshake with the Email server (ex: AWS SES) and communicates with it. Acts as a proxy between the callee's local instance and the AWS Nitro Enclave and also acts as a proxy (conceptually) between the Email server and the Nitro Enclave.

## Files Description for Main Files

- **setup.sh**: Setup script to install necessary dependencies.
- **run_client.sh**: Script to run the WebSocket server.
- **ws_server.py**: The WebSocket server.

- **client_aws.py**: This script was used to communicate with the Enclave and mocking the Dolphin client actions, while running in the same EC2 where the Enclave is. This is redundant now since the local setup with websocket connections with the EC2 was introduced. It is also outdated now. But kept in the repository for demonstration purposes.

Most of the other files are used for the TLS handshake. Rest of the files were used by the now outdated client_aws.py for attestation document verification.

## Prerequisites 

- Have the code in the Nitro Enclave run in another terminal (not on debugging mode).
- Provide the Enclave-id and the port as inputs when running the script.
- Run the local websocket client to initiate the communication process.

## Setup Instructions

1. Setup Virtual Environment

```sh
 ./setup.sh
```

2. Run WebSocket Server

```sh
 ./run_server.sh <enclave-id> <port>
```

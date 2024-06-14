# Local Setup

## Overview

The project mainly demonstrates the programme the callee of Dolphin should run locally. It should make a web socket connection with the EC2 server and forward the instructions coming from the caller via the original Dolphin setting. However, for demonstration purposes, the original Dolphin setup is cut-off (how the data gets converted to audio and arrives as a call to the callee where it would be decoded back to data). Instead this programme would mock the caller actions and orchestrate the whole communication process. The average execution time for the end to end process would also be calculated.

There is another programme to demonstrate how the attestation process can be performed locally without any internet accesss.

## Files Description

- **setup.sh**: Setup script to install necessary dependencies.
- **root.pem**: Root certificate for verification.
- **attestation_verifier.py**: Verifies the attestation document.
- **requirements.txt**: Required Python packages.
- **run_client.sh**: Script to run the WebSocket client.
- **ws_local_client.py**: Main WebSocket client script.

- **attest_without_internet.py**: Script to attest without an internet connection.
- **check_local_attestation.sh**: Shell script to test local attestation.

## Prerequisites 

- Have python installed.
- For the main task: Run the parent instance and the Enclave code and adjust the public IP address to have the same value of the EC2 machine that runs above mentioned programmes.
- For local attestation demo: copy paste from the console the b64 string of a received attestation document and the corresponding PCR0 value and replace the hardcoded values in the file

## Setup Instructions

1. Setup Virtual Environment

```sh
 ./setup.sh
```

2. Run WebSocket Client

```sh
 ./run_client.sh
```

3. Run Local Attestation without Internet

```sh
 ./check_local_attestation.sh
```


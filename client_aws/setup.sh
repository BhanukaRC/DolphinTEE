#!/bin/bash

# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install required packages
pip install -r requirements.txt

# Remove the OpenSSL directory if it exists (adjust the path as needed)
rm -rf venv/lib64/python3.7/site-packages/OpenSSL/

# Install specific version of pyOpenSSL
pip3 install pyOpenSSL==23.1.1

# Deactivate the virtual environment
deactivate
~                   
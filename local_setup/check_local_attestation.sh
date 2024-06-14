#!/bin/bash

# Activate the virtual environment
source venv/bin/activate


# Turn off Wi-Fi
sudo nmcli radio wifi off

# Run the Python script
python3 attest_without_internet.py

# Turn on Wi-Fi
sudo nmcli radio wifi on
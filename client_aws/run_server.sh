#!/bin/bash

# Activate the virtual environment
source venv/bin/activate

# Run the Python script with specified arguments
python3 ws_server.py "$1" "$2"

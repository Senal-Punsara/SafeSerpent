#!/bin/bash

# Update package list
sudo apt-get update

# Install system packages
sudo apt-get install -y python3-pil python3-pil.imagetk python3-tk

# Install pip if not already installed
sudo apt-get install -y python3-pip

# Upgrade pip
python3 -m pip install --upgrade pip

# Install required Python libraries

pip3 install ttkbootstrap
pip3 install pillow
pip3 install cryptography


echo "All required libraries have been installed."



# get-pwnd
Final Project for CS378

## Requirements

python3, pip3

## Installation

    pip3 install -r requirements.txt

## Usage

Currently the tool only emulates scanning the network, 
but does try to connect to the target machine by using ssh/telnet.

    python3 getpwnd.py config/scan-config.txt

### Scan config sample

    213.180.204.3
    admin:password
    test:test
    user:123456

Created by:
* Nicholas Kantor
* Ian Davis
* William Yager
* Christopher Lee

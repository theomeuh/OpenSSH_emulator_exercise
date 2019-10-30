# TL_OpenSSH_emulator_with_python
This project emulates the creation of a certification network via equipments.
Equipments exchange x509 certificate through socktets.

## Requirements
* python3.7
* pipenv


## Installation 
`pipenv install`

## Usage
To start one equipment in one terminal:
`pipenv shell`
`python main.py`

NB: To start n equipment, repeat these steps in n terminal.

To connect two equipments:
- set one equipment as a server
- set the other one as a client
The server automatically listens on localhost port 8888 and the client tries to connect to it.

Then the following checks are made:
- Have we met before ? Yes: no human needed
- Do my friends know you ? Yes: no human needed
- Else I ask my human if we can connect ?

## Test
To run test, be sure to install dev dependencies:
`pipenv install --dev`

Then tests can be run with:
`pytest`

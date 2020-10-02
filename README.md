# qoin

Simple implementation of the blockchain

## Installation

### Server

An example of configuration file is provided under `src/etc` directory, `server.conf.example`.

All fields are required, and a secret key must be generated. You can use openssl library to generate it.

`openssl rand -hex 16`

### Website

An example of configuration file is provided under `etc` directory.

Like the server parameters, all fields are required, and a diffrent secret key must be generated. You can use openssl library to generate it.

`openssl rand -hex 16`

### Miner

An example of configuration file is provided under `etc` directory.

Miner can be authenticated with user credentials or not.

## Architecture

The system is not distributed, but the services have been designed to work on different hosts.

Server is the leader of the cluster. One server instance to make the blockchain work.

Then, at least one miner instance must be declared in order to process the transactions, and optionally one website instance to provide web interface.

## Interfaces

### Python

You can use python and the `RPYC` library (https://rpyc.readthedocs.io/en/latest) to connect to the master and calls commands. The exhaustive list is below:

* **authenticate_user**: authenticate an user on the server
* **transaction**: transfer amount of Qoin from an account to another
* **history**: get the history of an account
* **get_account**: get the history and the balance of an account
* **get_balance**: get the balance of an account
* **get_last_trs**: get the last transactions since a timestamp for an account
* **list_users**: list users registered on the server
* **master_create_user**: register a new user on the server ; requires administrator privileges

* **master_credit**: transfer amount of Qoin from the system to an account ; requires administrator privileges
* **auth_service**: authenticate a service on the server
* **declare_service**: declare a new service linked to a user
* **service_refresh_key**: remove the old key of a service and generate a new one
* **get_services_status**: return the status of the services registered for a user

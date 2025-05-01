# pychatbox
A python-based, secure chat application 

This application was developed to learn about sockets in Python. It ended up making me learn these topics:

* ### Sockets

  Basics of creating TCP sockets, accepting/binding connections, handling multiple connections, properly closing connections

* ### Multi-Threading

  Using threads to distribute work and establish idle threads for listening for messages continuously. Using thread safe python structures like Queue and using the concept of "checking the queue"/consumer-producer queue.

* ### Sqlite
  
  Managing a user database for authentication purposes. Using basic SQL queries to update/retrieve data from the database.
  
* ### Tkinter GUI
  
  GUI becomes important to handle the visual nature of a chat app, which is not satisfied or is not feasible in a terminal enviornment.
  
* ### Cryptography
  
  Implemented a secure chat model using AES (for encrypting messages), HMAC for integrity checks and wrapped sockets with SSL/TLS.
  
## Installation
  
  Code requires the installation of the pycryptodome library. Use pip to install it.

## Usage 
  
  To use the SSL service, you can create your own self-signed certificates using openssl.
  Run the server code and then you can have multiple clients authenticate into the server. Rest is simple and self-explanatory.
  
## Screenshots

![alt text](https://github.com/return-z/pychatbox/blob/master/screenshots/client_connect_page.PNG?raw=true)

![alt text](https://github.com/return-z/pychatbox/blob/master/screenshots/server_and_client.PNG)

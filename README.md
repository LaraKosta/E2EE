#####################################################################################
#####################################################################################
###############################  E2EE Project #######################################
############################### By Lior Lazari ######################################
#####################################################################################
#####################################################################################

This Project is simulates End-to-end encryption 
The project aims to demonstrate a protocol that enables secure message transmission, 
ensuring encrypted messages reach their destination safely. 
The project is divided into two parts: server-side and client-side.

server
-------
The server maintains a database named "user_db" to store information about authenticated clients.
Additionally, for each client, it maintains a "message_queue" database that stores messages sent
to that client, even when they are not connected to the server.

The server listens on port 5000 to accept new clients wishing to connect to the service. 
(Since I ran the server and clients on the same computer, simply in different cmd windows,
the server's host is set to 127.0.0.1 at the client.)

The server receives requests in JSON format and processes client requests for "send", "fetch", and "quit".
The server's encryption method is asymmetric encryption of type EC (further details to follow). 
The server holds 2 fixed keys: a private key never sent to clients, and a public key used to verify client signatures.

client
-------
Each client has a constant ECC key initialized once and stored in the database.
When a client attempts to connect to the service for the first time, the server requests their phone
number (assuming it's a unique number) and starts an authentication process.

The client generates a new private key and stores it as a .pem file, then attempts to register with the
 server. The server requests them to authenticate by sending a one-time OPT code to confirm their 
 identity (assuming the cmd is a secure channel).

 After authentication, the server stores their data in "user_db", and the client can now send and receive messages.

 Each time a message is sent, the client retrieves a shared key from the server's public key and uses the AES encryption algorithm.

 Messages are stored on the server if the client is not connected to the service, allowing them to be accessed when they reconnect.

 ----------------------------------------------------------------------------------------------------------------------------------

 This outlines the basic functionalities and setup of the project involving secure message transmission between a server and clients.


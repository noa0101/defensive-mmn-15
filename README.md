author: Noa Ben Israel

This project is the final project (maman 15) for the course Defensive Systems Programming.
It includes an implementation of a server in python that serves as a backup server using the local disk,
and a cpp client that sends requests to the server to demonstrate it's action.
The server and client work according to the protocol specified in the course booklet.
The server creates a folder on the disk with the path "C:\backup_server", and in this folder it creates backups for the client.


The zip file I have submitted contains:
	- This readme file
	- A file specifying vulnerabilities in the protocol (answer to question 2)

	The code files:
	- a folder named "client" containing 4 header files and 6 cpp files that include the implementation of the client. 
	- a folder named "server" containing 6 python files that have the implementation of the server's operation.
	for further information on the content and purpose of each file, please view the documentation at the top of each file.

	- A video with a demonstration run of the server and client.
		
	

Running the project:
The server may be ran through cmd using the line "python server.py".
For the server to run, the python interpreter installed must include the library pyCryptodome.
To specify the port on which the server will listen, add a file named "port.info" in which there is the wanted port number. If no such file is found, the server will listen on a default port number 1256.
Required python version: 3.12.

In order to run the server, the cpp and header files should be put into a visual studio solution that is configured to work with libraries boost and CryptoPP. Through visual studio the solution can be build, and then the server may be ran through visual studio or through cmd using the line "<execution file name>.exe".
Required cpp version: c++17 or further.
For the client to run, there should exist two additional files:
	1. "transfer.info",  in the same location as the execution file, containing 3 lines:
		IP address + ':' + port number
		The name of the client (a string up to 100 chars)
		A path to the file the client should send
	
	2. The file the client should send, in the location specified in transfer.info.
If either of these files do not exist or are not of the expected format, the client will stop it's activity.

After running:
	- Once the server and client have ran, a series of messages should appear in the terminal, presenting the course of communication between them.

	- Once running the project, a file containing an SQL database will be created in the directory of the server files. 
	That file contains information about the clients that have registered and the files they have sent. 
	In case the server stops running, it will reload that database and retain the information.
	All that is relevant for the bonus question (question number 3).

	- Also, the files "me.info" and "priv.key" will be created in the location of the execution file of the client.

	- If the client requests to send a file for backup (which the client implemented here does), there will be a copy of this file under the path 
	"C:\backup_server\<uuid generated for the client by the server>\<file name>".


Of course, other clients may communicate with the server, as long as they follow the specified communication protocol.

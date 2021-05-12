# The-Trivial-File-Transfer-Protocol-TFTP-

## Intro 🚪
Transfering files over the internet has a long history, it’s useful for companies distributing their code, 
as they’ll not need to have customers come visit some special shops to buy their software for example, or sharing files across devices in your house.

##Programming Languages 🌍
You can deliver using the following languages: Python 


* Implementing a protocol on your own is a new thing you’ll be exposed to, along with reading, understanding and implementing a technical document. 
Breaking this barrier (in the context of computer networks) is the main objective of this project.

 ## ℹ️ Requirements
### Operating System: Linux  or windows 
*  We’ll be transferring files. Not emails.
*  Use the octet mode of transfer. Not netascii or others.
*  The transfer identifiers (TID's) are simply the UDP port number, the TID notation is used across the RFC
*  The server runs on port 69 by default
*  8-bit format means “byte”
## How to test 
Sure! Here you go. (Make sure wireshark is running on the loopback interface)

Assuming that you’re working on a TFTP client; open a UDP socket then send the following (copy this code and modify the variable names as needed, leave the values as it)

```python 
r_bytes = bytearray([0, 1, 97, 46, 116, 120, 116, 0, 111, 99, 116, 101, 116, 0])
udp_socket.sendto(r_bytes, ("127.0.0.1", 69))
```
Now you should see a reply from the server. This bytearray is the equivalent of sending a request to read a file named: a.txt as wireshark will show you.
Wireshark

## Wireshark
Wireshark is the simplest method to make sure you're at least emitting TFTP packets, the packet type will appear as TFTP if your packets are correctly formatted. This is the first good sign you're on the right track.
TFTP Software
Since your code won't be running in the wild 🏖, you have to make sure it's running against real software written by other people. Download and install software for the other party of TFTP, e.g. if you're implementing a server, install a TFTP client and vice versa, then use this software to test your own implementation. 


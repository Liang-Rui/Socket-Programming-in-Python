# Introduction

A computer network project aims at implement a reliable transport protocol called STP (Simple Transport Protocol) over the UDP protocol using Python. STP will include most of the features that are implemented in TCP, including timeout, ACK, sequence number etc. For example, a file is to be transferred from the Sender to the Receiver like the following figure shows.

![Screen Shot 2020-04-02 at 6.29.28 pm](https://i.imgur.com/uQpE5TC.png)

List of features implemented by STP:

- A three-way handshake (SYN, SYN+ACK, ACK) for the connection establishment. 
- A four-segment (FIN, ACK, FIN, ACK) connection termination.
- Sender must maintain a single-timer for timeout operation.
- Sender should implement all the features mentioned in Section 3.5.4 of the text (*Computer Network A Top Down Approach 7ed*), with the exception of doubling the timeout. 
- Receiver should implement the features mentioned in Section 3.5.4 of the text (*Computer Network A Top Down Approach 7ed*). 
- STP is a byte-stream oriented protocol.
- MSS (Maximum segment size) is the maximum number of bytes of data that your STP segment can contain. 
- Another input argument for Sender is Maximum Window Size (MWS). MWS is the maximum number of un-acknowledged bytes that the Sender can have at any time.
- Even though we use UDP, since the sender and receiver will mostly be running on machines that are within close proximity of each other (e.g.: on the same Ethernet LAN or even on the same physical machine), there will be no real possibility of datagrams being dropped/delayed/corrupted. In order to test the reliability of STP protocol, it is imperative to introduce artificially induced packet loss, delays and corruption etc. For this purpose, a Packet Loss and Delay (PLD) Module is implemented as part of the Sender program. 



PLEASE REFERENCE THIS PROJECT PROPERLY OTHERWISE YOU MAY INVOLVE IN PLAGIARISM!


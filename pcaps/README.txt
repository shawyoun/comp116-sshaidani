Shawyoun Shaidani: Assignment 1

1) There are 861 packets
2) FTP
3) The credentials are visible as plain text, and the files are sent unencrypted
4) SFTP or FTPS
5) The server is 192.168.1.8
6) defcon:m1ngisablowhard
7) 6 files
8) COaqQWnU8AAwX3K.jpg, CDkv69qUsAAq8zN.jpg, CNsAEaYUYAARuaj.jpg, CLu-m0MWoAAgijkr.jpg, CKBXgmOWcAAtc4u.jpg, CJoWmoOUkAAAYpx.jpg
9) See "image1," "image2", etc.

10) 77,982 packets
11) 1 user/pass pair (larry@radsot.com:Z3lenzmej)
12) I ran ettercap against the pcap file, then piped its output into grep and searched for “PASS.”
13) For larry@radsot.com:Z3lenzmej, the protocol was IMAP, the server IP was 87.120.13.118, the domain was mail.radsot.com, and the port number was 143.
14) Of the one pair that I found, it was legitimate.

15) 3 user/pass pairs (nab01620@nifty.com:Nifty->takirin1) (jeff:asdasdasd), (seymore:butts)
16) For nab01620@nifty.com:Nifty->takirin1, the protocol was IMAP, the server IP was 210.131.4.155, and the port 143. 
For jeff:asdasdasd, the protocol was HTTP, the server IP was 54.191.109.23, the domain was ec2-54-191-109-23.us.west-2.computer.amazonaws.com, and port 80. 
For seymore:butts, the protocol was HTTP, the server IP was 162.222.171.208, domain was forum.defcon.org, and port 80.
17) nab01620@nifty.com:Nifty->takirin1 is legitimate
19) I searched for the IP address of the host, filtered the packets by that address, then followed the TCP stream to see what the server’s response was (OK or denied).
20) Use a secure protocol when logging in. 


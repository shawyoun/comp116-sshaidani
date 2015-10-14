Comp 116, Assignment 2
Shawyoun Shaidani

I have implemented an alarm which can checks for certain kinds of scans against a live network in real time. It can correctly identify NULL, FIN, and XMAS TCP packets, as well as credit card numbers that are sent in the clear over HTTP.
It also makes an attempt to identify all other kinds of Nmap scans, as well as Nikto scans. These can only be identified, however, if their names are encoded as part of the payload. Scans are often sent without a payload, making them invisible to this alarm (aside from the special cases we're explicitly looking for).

This alarm can also take in a web log in Apache's Combined Log Format and analyze it for attacks that have already occurred. 
Simply by checking for characteristic patterns in the parsed string, it is capable of identifying Nmap, Nikto, Masscan, attackers looking for phpMyAdmin information, attackers looking for shellshock vulnerability (with the characteristic 'empty function definition' in the payload), as well as potential shellcode. 

I have spent approximately 30 hours on this assignment, the vast majority of which was background research, and only a few of which were dedicated to actual coding / testing.

The heuristics have significant limitations:
The Regex's for credit cards may result in false positives because some payloads may just have numbers that happen to look like that. 
In addition, not all nmap scans are going to make their signatures clear in the payloads (this applies for both the sniffing and web server logs), so certain scans may slip through the cracks. 
Also, this alarm does nothing to address the possibility that someone is using a decoy for their source IP address.

If I could add to this project in the future, I would add support for UDP scans because I know that's another common protocol for nmap.
Also, since we're sniffing, we would have to work with an unswitched network if we want network-wide coverage (instead of just my computer). I could add an ARP spoofer so that I can listen to all traffic on a switched network, and detect incidents.
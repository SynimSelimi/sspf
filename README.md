# sspf
#### *Cyber Deception Framework*

## Usage
1.	lanusrs
2.	arp show
3.	tableflush
4.	online? {target_ip}
5.	sniff {interface} [filepath]
6.	arp {interface} {target_ip} {-res | req}
7.	dns {interface} {file | {link} {dns_ip}}
8.	mitm {interface} {target_ip} {-dos | -spy}
9.	mac {interface} {show | rand | orig | {new_mac}}
10. findmac {target_ip}
11.	ssl {filepath}
12.	arpp
13. sniffp
14. dnsp {link}
15. netconfig

## Installation
Please install **Kali Linux** and run the following commands OR install the tools and libraries specified in **requirements.txt**

```sh
1. sudo apt-get update
2. sudo apt-get install arptables
3. sudo apt-get install python3
4. sudo apt-get -y install python3-pip
5. pip3 install scapy
```

## Running the framework
Run the framework using **python3 sspf.py** OR create an executable and run it using **./sspf**.

The given functionalities are rather self-explanatory.

## Contributing
Please read CONTRIBUTING.md and CODE_OF_CONDUCT.md for details on our pull request submission process and our code of conduct. Note that the code of conduct is to followed in all interactions with the project. Templates are provided in .github/ISSUE_TEMPLATE/ for any bug reports or new feature requests.

## Acknowledgements
This work would not be possible without the direct or indirect influence and source code from the open source community. Through this open source non-commercial software we are trying to acknowledge and further the contribution.

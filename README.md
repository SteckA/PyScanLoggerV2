# PyScanLoggerV2
A Python script that will detect port scanning and log the information. 
Inspired by John Lin's pyscanlogger found <a href="https://github.com/John-Lin/pyscanlogger">here</a>
#Required Packages
Can be installed with pip
-dpkt
-pypcap
-netifaces
# Features
Detects interfaces with ipaddress (ignores loopback and vm interfaces)
Detects ip address changes
Detects interface changes 
Can listen to multiple interfaces using multiprocessing
Can perform whois lookup on attacker
# Usage
Must run as sudo 
-v --verbose: prints more information to console
-f --logfile: allows for custom log location
-w --whois: will perform whois lookup
# PyScanLoggerV2
A Python script that will detect port scanning and log the information. 
Inspired by John Lin's pyscanlogger found <a href="https://github.com/John-Lin/pyscanlogger">here</a>.
## Required Packages
Can be installed with pip
<br>
<ul>
	<li>dpkt</li>
	<li>pypcap</li>
	<li>netifaces</li>
</ul>
## Features
<ul>
	<li>Detects which type of scan was performed</li>
	<li>Detects interfaces with ip address (ignores loopback and vm interfaces)</li>
	<li>Can listen to multiple interfaces using multiprocessing</li>
	<li>Detects ip address change</li>
	<li>Detects interface change</li>	
	<li>Can perform whois lookup on attacker</li>
	<li>Platform independent</li>
</ul>
## Usage
<i>Must run as sudo</i><br> 
`sudo python pyscanloggerv2.py`<br>
<code>-h, --help       show this help message and exit</code><br>
<code>-v, --verbose    Prints scan detections to stdout</code><br>
<code>-f, --logfile   Desired path of log file</code></br>
<code>-w, --whois      Runs whois against scanner's ip</code>
## Logging
- Logs to /var/log/pyscan.log by default<br>
- Triggers when 20 ports have been hit in 3 minutes from same ip address. The threshold can be changed at the top of the script for more/less sensitive triggering.
# PyScanLoggerV2
A Python script that will detect port scanning and log the information. 
Inspired by John Lin's pyscanlogger found <a href="https://github.com/John-Lin/pyscanlogger">here</a>.
#Required Packages
Can be installed with pip
<br>
<ul>
	<li>dpkt</li>
	<li>pypcap</li>
	<li>netifaces</li>
</ul>
# Features
<ul>
	<li>Detects interfaces with ipaddress (ignores loopback and vm interfaces)</li>
	<li>Detects ip address changes</li>
	<li>Detects interface changes</li>
	<li>Can listen to multiple interfaces using multiprocessing</li>
	<li>Can perform whois lookup on attacker</li>
</ul>
# Usage
<i>Must run as sudo</i><br> 
<code>-h, --help       show this help message and exit</code><br>
<code>-v, --verbose    Prints scan detections to stdout</code><br>
<code>-f , --logfile   Desired path of log file</code></br>
<code>-w, --whois      Runs whois against scanner's ip</code>
# Project-2-Hands-on-expirience
To detect and analyze suspicious network activities such as TCP port scans and SSH brute-force attacks using Snort IDS (Version 2) with custom detection rules and fine-tuned configurations.

first update and upgrade ubantu or kali
command---sudo apt update && sudo apt upgrade 

install snort version 2.9.0

command----sudo apt install snort 

then after give your machine ip in the propt ----example:192.168.80.133

/etc/snort/rules/local.rules

1.alert tcp any any -> any 22 (msg:"[ALERT] Possible SSH Brute Force Attempt"; flow:to_server,established; content:"SSH"; nocase; threshold:type threshold, track by_src, count 10, seconds 60; 
sid:100002; rev:1;)
port 22 – Targets SSH service.

content:"SSH" – Looks for SSH-related traffic (can be tuned further).

threshold – 10 attempts in 60 seconds from same IP triggers an alert.

Catches brute force attacks (e.g., Hydra/Medusa).


2.alert tcp any any -> any 1:1024 (msg:"[ALERT] Possible TCP SYN Port Scan Detected"; flags:S; threshold:type threshold, track by_src, count 20, seconds 10; sid:100001; rev:1;)
flags:S – Matches only SYN packets.

threshold – Triggers an alert if 20 SYN packets are sent from the same IP in 10 seconds.

sid:100001 – Unique Snort rule ID.

Detects scanning behavior like nmap -sS

/etc/snort/snort.conf

include $RULE_PATH/local.rules

sudo snort -A console -q -u snort -g snort -c /etc/snort/snort.conf -i adapter---ens33,rth0 etc  (show loges)

alert tcp any any -> any 21 (msg:"[ALERT] FTP Login Attempt Detected"; content:"USER "; nocase; sid:1000002; rev:1;)

Monitors traffic to port 21 (FTP).

Alerts when a username is being sent (typically starts with USER).

Useful for detecting brute-force login attempts.

nmap -sS <target-ip>----check nmap show snort loges tcp syn--reference screenshort

example:nmap -sS 192.168.1.10

hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target-ip>-----for burp suite login attempts show in snort

example:hydra -l root -P passwords.txt ssh://192.168.1.10

sudo snort -A console -q -u snort -g snort -c /etc/snort/snort.conf -i eth0----run snort

Successfully simulated TCP SYN Port Scan and SSH Brute Force attacks in a controlled environment using Nmap and Hydra. Custom Snort rules triggered real-time alerts. Detection quality was high, with minimal false positives. These experiments enhance my understanding of intrusion detection systems and rule tuning for accurate threat detection.









# Walkthrough

After starting the machine, we get the IP address of our target. 
For convenience i create an environment variable that contains the IP:

```
export ip=10.10.10.10
```

Now we perform a portscan using nmap
```
nmap -p- $ip -T4 -O -osscan-guess
```
We use option
-p- to scan for all ports,
-T4 for selecting a fast portscan (T<0-5>)
-O to fingerprint the operating system
-osscan-guess to guess the operating system when the OS fingerprint (-O) is inaccurate

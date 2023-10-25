
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

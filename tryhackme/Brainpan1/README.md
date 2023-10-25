
# Walkthrough

After starting the machine, we get the IP address of our target. 
For convenience i create an environment variable that contains the IP:

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/a74a4cc2-8987-47e9-b785-e2d4172dc58e)

Now we perform a portscan using nmap
```
nmap -p- $ip -T4 -O -osscan-guess
```

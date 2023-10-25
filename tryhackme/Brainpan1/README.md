
# Walkthrough

Before starting the machine, we connect to the OpenVPN network using openvpn:
```
sudo openvpn ./vpn-file
```

After starting the machine, we get the IP address of our target. 
For convenience i create an environment variable that contains the IP:
<br>
```
export ip=10.10.10.10
```
<br>
Now we perform a portscan using nmap
```
nmap -p- $ip -T4 -O -osscan-guess
```
<br>

We use option:<br>
**-p-** to scan for all ports,<br>
**-T4** for selecting a fast portscan (T<0-5>)<br>
**-O** to fingerprint the operating system<br>
**-osscan-guess** to guess the operating system when the OS fingerprint (-O) is inaccurate<br>


![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/00872e20-ea3e-418f-b303-02ad7c527e94)

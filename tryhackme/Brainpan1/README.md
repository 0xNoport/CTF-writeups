
# Walkthrough

Before starting the machine, we connect to the OpenVPN network using openvpn:
```
sudo openvpn ./vpn-file
```

After starting the machine, we get the IP address of our target. 
For convenience i create an environment variable that contains the IP:

```
export ip=10.10.10.10
```

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

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/9d24dd32-b1f3-4a14-b2c0-fb1d470649cb)

According to the output of nmap, there is a webserver running on port 10000. Now, we will scan the webserver and search for hidden files/folders using gobuster:
```
gobuster dir -u http://$ip:10000/ -w /usr/share/wordlists/ -x ".exe"
```
**-u** to specify the url<br>
**-w** to specify a wordlist<br>
**-x** to specify a file extension that should be added to each entry to the list additionally<br>

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/5e2a90d5-0dc7-4372-aabf-8c5eac041671)

By running the previous command, we find a hidden directory that is accessible from the webserver: /bin. We do manual enumeration and find a file called brainpan.exe

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/1ef441b5-6780-4677-888b-ef6bf63918e6)


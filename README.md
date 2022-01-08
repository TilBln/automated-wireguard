# automated-wireguard
### A python-script to securely automate the basic installation as well as the generation of multiple clients of your linux wireguard client

The Script will do the basic installation and adds after every re-execution a new client with a unique ipv4. 

**first-time-installation on raw linux-server**

- log in to privileged user:
```
sudo su
```
- update your system and install wireguard:
```
apt-get update -y && apt-get upgrade -y && apt-get install wireguard -y
cd /etc/wireguard
umask 077
```
- turn on net.ipv4.ip_forward:
```
perl -pi -e 's/#{1,}?net.ipv4.ip_forward ?= ?(0|1)/net.ipv4.ip_forward = 1/g' /etc/sysctl.conf
reboot now
sudo su
cd /etc/wireguard
```
- install the installation script:
```
wget
```
- adjust the variables at the top of the script:
```
nano automated_wg.py
```
- execute the script:
```
python3 automated_wg.py
```
- follow the instructions above in your shell to generate qr-code for the mobile app:
```
cat qrencode ansiutf8...
```
- adjust permissions:
```
chown -R root:root /etc/wireguard/
chmod -R og-rwx /etc/wireguard/*
```
**generation of following clients**

- just execute the script again:
```
cd /etc/wireguard
python3 automated_wg.py
```
- generate qr-code as shown above:
```
cat qrencode ansiutf8...
```
- adjust permissions:
```
chown -R root:root /etc/wireguard/
chmod -R og-rwx /etc/wireguard/*
```

##That's it!##

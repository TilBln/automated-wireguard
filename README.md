# AutomatedWireGuard
### A python-script to securely automate the first-time-installation as well as the generation of multiple clients on your Linux WireGuard-server.

The Script will do the basic installation and adds after every re-execution a new client with a unique ipv4.
You can costumize multiple variables while first-time-installation, e.g. the config file names or the used port.
The total number of existing clients is saved in /etc/wireguard/total_clients.txt and the variables of the first-time-installation are being saved in /etc/wireguard/variables.txt. If you want to change any variables, just delete the variables.txt. Next time you want to create a new client, the script will ask you for each variable again.

!For Proxmox-Users it is recommended to just download the file into a ubuntu-22.04 container template and execute it!

**first-time-installation on raw linux-server / Proxmox-Container**

- log in to privileged user:
```
sudo su
```
- download the script:
```
wget https://github.com/TilBln/automated-wireguard/raw/main/automated_wg.py
```
- execute the script:
```
python3 automated_wg.py
```
- follow instrucions displayed in your command-prompt.

**generation of following clients**

- just re-execute the script to generate a new client.
```
python3 automated_wg.py
```

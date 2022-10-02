from pathlib import Path
import os
os.system('ls')


print('Welcome to the AutomatedWireGuard-Script.\nIt will help you install a fully working WireGuard-Server.\n')
##check whether the server keyfiles already exist
server_public_keyfile = Path('/etc/wireguard/server-public.key')
server_private_keyfile = Path('/etc/wireguard/server-private.key')

if server_public_keyfile.is_file() and server_private_keyfile.is_file():
    print('---Welcome to the AutomatedWireGuard-Script---\nNow creating a new Client...')
    read_server_public_key = open('/etc/wireguard/server-public.key', 'r')
    lines_server_public_key = read_server_public_key.readlines()
    server_public_key = lines_server_public_key[-1]
    
    read_server_private_key = open('/etc/wireguard/server-private.key', 'r')
    lines_server_private_key = read_server_private_key.readlines()
    server_private_key = lines_server_private_key[-1]

    first_time_installation_marker = 0
else:
    print('---Welcome to the AutomatedWireGuard-Script---\nIt will help you install a fully working WireGuard-Server.\nDetected first time installation. Installing Updates, WireGuard, generating keys and installing qrencode...')
    update_check = input('Do you want to update and upgrade your system? (y/n)')
    if update_check == 'y':
        os.system('apt-get update -y && apt-get upgrade -y')
    check_install_wg = input("Do you want to install Wireguard now? (y/n) ")
    if check_install_wg == 'y':
        os.system('apt-get install wireguard -y')
        os.system("perl -pi -e 's/#{1,}?net.ipv4.ip_forward ?= ?(0|1)/net.ipv4.ip_forward = 1/g' /etc/sysctl.conf")
    os.system('wg genkey | tee /etc/wireguard/server-private.key | wg pubkey > /etc/wireguard/server-public.key')

    read_server_public_key = open('/etc/wireguard/server-public.key', 'r')
    lines_server_public_key = read_server_public_key.readlines()
    server_public_key = lines_server_public_key[-1]
    
    read_server_private_key = open('/etc/wireguard/server-private.key', 'r')
    lines_server_private_key = read_server_private_key.readlines()
    server_private_key = lines_server_private_key[-1]

    os.system('sudo apt-get install qrencode -y')
    first_time_installation_marker = 1


## checking whether variables.txt does exist
variables_check = Path('/etc/wireguard/variables.txt')
if variables_check.is_file():
    vc = 1
else: 
    vc = 0

## user is adjusting each variable on first time installation
if first_time_installation_marker == 1 or vc == 0:
    clients_conf_file_name = input('How should the client config file be named? It will look like this: client1.conf - For default (client) press enter. ')
    if clients_conf_file_name == '':
        clients_conf_file_name = 'client'
    first_ip_address_client = input('Which should be the first client-ipv4? For default (10.10.100.2) press enter. ')
    if first_ip_address_client == '':
        first_ip_address_client = '10.10.100.2'
    AllowedIPs = input('Which IP addresses should be allowed? For default (0.0.0.0/0, ::/0) press enter. ')
    if AllowedIPs == '':
        AllowedIPs = '0.0.0.0/0, ::/0'
    address_wg0_conf = input('Which private IP address should the server have? For default (100.64.0.1/24) press enter. ')
    if address_wg0_conf == '':
        address_wg0_conf = '100.64.0.1/24'
    os.system('ip addr')
    ethernet_port = input('Which ethernet port is used for target network? It can be looked up above. For default (eth0) press enter. ')
    if ethernet_port == '':
        ethernet_port = 'eth0'
    wg_port = input ('Which port (needs to be open!) should be used for your wireguard? For default (51900) press enter. ')
    if wg_port == '':
        wg_port = '51900'
    DNS = input('What DNS should be used by your clients? For default CloudFlare (1.0.0.1) press enter. ')
    if DNS == '':
        DNS = '1.0.0.1'
    domain = input('Via which domain should the WireGuard-server be reached? (E.g. your.domain.com) ')

## entered values are getting saved in variables.txt
    variables = open('/etc/wireguard/variables.txt', 'w')
    variables.write(clients_conf_file_name + ';' + first_ip_address_client + ';' + AllowedIPs + ';' + address_wg0_conf + ';' + ethernet_port + ';' + wg_port + ';' + DNS + ';' + domain)
    variables.close()
## the script is reading the variables.txt while creating multiple clients
else:
    variables = open('/etc/wireguard/variables.txt', 'r')
    line_variables = variables.readlines()[-1]
    clients_conf_file_name = line_variables.split(';')[-8]
    first_ip_address_client = line_variables.split(';')[-7]
    AllowedIPs = line_variables.split(';')[-6]
    address_wg0_conf = line_variables.split(';')[-5]
    ethernet_port = line_variables.split(';')[-4]
    wg_port = line_variables.split(';')[-3]
    DNS = line_variables.split(';')[-2]
    domain = line_variables.split(';')[-1]
    variables.close()

## check whether the wg0.conf in /etc/wireguard already exists
wgconf = Path('/etc/wireguard/wg0.conf')
if wgconf.is_file():
    print('detected existing wg0.conf')
else:
    print('creating a wg0.conf')
    wg0_conf = open('/etc/wireguard/wg0.conf', 'w')
    wg0_conf.write('[Interface]\nAddress = ' + str(address_wg0_conf)+ '\nSaveConfig = true\nPostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ' + str(ethernet_port) + ' -j MASQUERADE\nPostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ' + str(ethernet_port) + ' -j MASQUERADE\nListenPort = ' + str(wg_port) + '\nPrivateKey = ' + str(server_private_key) + '\n\n')
    wg0_conf.close()

## total_clients.txt is being created or adjusted
total_clients = Path('/etc/wireguard/total_clients.txt')
if total_clients.is_file():
    total_clients_write = open('/etc/wireguard/total_clients.txt', 'a')
    total_clients_read = open('/etc/wireguard/total_clients.txt', 'r')
    line_total_clients = total_clients_read.readlines()
    last_line_total_clients_read = line_total_clients[-1]
    new_client_number = int(last_line_total_clients_read) + 1
    total_clients_write.write(str(new_client_number) + '\n') 
else: 
    total_clients_write = open('/etc/wireguard/total_clients.txt', 'a')
    total_clients_write.write('1\n')
    total_clients_write.close()
    total_clients_read = open('/etc/wireguard/total_clients.txt', 'r')
    line_total_clients = total_clients_read.readlines()
    last_line_total_clients_read = line_total_clients[-1]
    new_client_number = 1

## the keys for the new client are being generated
print('creating private and public keys')
os.system('wg genkey | tee /etc/wireguard/' + clients_conf_file_name + str(new_client_number) + '-private.key | wg pubkey > /etc/wireguard/' + clients_conf_file_name + str(new_client_number) + ('-public.key'))
## clientx-public.key and clientx-private.key were generated

## the new client keys are being read...
key_open_public = open('/etc/wireguard/' + clients_conf_file_name + str(new_client_number) + '-public.key', 'r')
key_open_private = open('/etc/wireguard/' + clients_conf_file_name + str(new_client_number) + '-private.key', 'r')

line_key_open_public = key_open_public.readlines()
line_key_open_private = key_open_private.readlines()

last_line_key_open_public = line_key_open_public[-1]
last_line_key_open_private = line_key_open_private[-1]

## ...and will be pasted into a new .conf together with the interface
last_number_ip_address_client_new = int(first_ip_address_client.split('.')[-1]) + (new_client_number - 1)
first_numbers_ip_address_client = str(first_ip_address_client.split('.')[-4]) + '.' + str(first_ip_address_client.split('.')[-3]) + '.' + str(first_ip_address_client.split('.')[-2]) + '.'
new_client_ip_address = str(first_numbers_ip_address_client) + str(last_number_ip_address_client_new) + '/32'
Endpoint = domain + ':' + str(wg_port)
client_conf = open('/etc/wireguard/' + clients_conf_file_name + str(new_client_number) + '.conf', 'a')
client_conf.write('[Interface]\nAddress = ' + str(new_client_ip_address) + '\nPrivateKey = ' + last_line_key_open_private + 'DNS = ' + str(DNS) + '\n\n[Peer]\nPublicKey = ' + str(server_public_key) + 'Endpoint = ' + str(Endpoint) + '\nAllowedIPs = ' + str(AllowedIPs) + '\n')
client_conf.close()
print('created a new client.conf')
if first_time_installation_marker != 1:
    os.system('wg-quick down wg0')
    print('stopped wireguard')
wg0_conf = open('/etc/wireguard/wg0.conf', 'a')
wg0_conf.write('\n[Peer]\nPublicKey = ' + last_line_key_open_public + 'AllowedIPs = ' + str(new_client_ip_address) + '\n\n')
wg0_conf.close()
print('added new client to wg0.conf')
if first_time_installation_marker != 1:
    os.system('wg-quick up wg0')
    print('started wireguard')

## on first time installation, the autostart is being activated.
if first_time_installation_marker == 1:
    os.system('systemctl enable wg-quick@wg0')

## print qr-code
print ('new client config file: /etc/wireguard/client' + str(new_client_number) + '.conf')
os.system('cat /etc/wireguard/client' + str(new_client_number) + '.conf | qrencode -t ansiutf8')
os.system('cat /etc/wireguard/client' + str(new_client_number) + '.conf | qrencode -t png -o /etc/wireguard/client' + str(new_client_number) + '-qr.png')
if first_time_installation_marker == 1:
    print('Wireguard is installed with a new, first client. Scan the displayed QR-Code in your mobile application. It is also saved as /etc/wireguard/client' + str(new_client_number) + '-qr.png . Now you can simply re-execute the script to add another new client. Reboot is required before use!!!')
else:
    print('Wireguard is running with a new client. Scan the displayed QR-Code in your mobile application. It is also saved as /etc/wireguard/client' + str(new_client_number) + '-qr.png')

## adjusting permissions
os.system('chown -R root:root /etc/wireguard/ && chmod -R og-rwx /etc/wireguard/*')

## everyting is being closed.
total_clients_read.close()
total_clients_write.close()
key_open_public.close()
key_open_private.close()
client_conf.close()

## finally offering instant reboot on first time installation
if first_time_installation_marker == 1:
    reboot_now = input('Do you want to reboot now? y/n ')
    if reboot_now == 'y':
        os.system('reboot now')
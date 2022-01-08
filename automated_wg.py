##variables##
clients_conf_file_name = 'client'           ## if necessary, adjust. name of the client config-files
first_part_ip_address_client = '10.10.100.' ## if necessary, adjust. first part of the client-ipv4
last_bracket_ip_address_client = '2'        ## if necessary, adjust. last bracket of the client-ipv4, client n receives 10.10.100.(2+n)/32 as ipv4
DNS = '1.0.0.1'                             ## if necessary, adjust. if there is no e.g. pihole, use: 8.8.8.8 (google) or 1.0.0.1 (cloudflare)
domain = 'your.domain.com'                  ## adjust!
AllowedIPs = '0.0.0.0/0, ::/0'
address_wg0_conf = '100.64.0.1/24'          ## if necessary, adjust. address of the wireguard-interface (may be looked up in wg0.conf after installation)
ethernet_port = 'eth0'                      ## adjust! look up your ethernet-interface via 'ip addr' in shell
wg_port = 51900                             ## adjust! fill in your preferred port of the endpoint to be reached from outside your network
#                                           #
#          BEGIN OF THE CODE                #
#############################################
#
#
#
#
#############################################
from pathlib import Path
import os
os.system('ls')

##check whether the server-keyfiles already exist

server_public_keyfile = Path('/etc/wireguard/server-public.key')
server_private_keyfile = Path('/etc/wireguard/server-private.key')

if server_public_keyfile.is_file() and server_private_keyfile.is_file():
    read_server_public_key = open('/etc/wireguard/server-public.key', 'r')
    lines_server_public_key = read_server_public_key.readlines()
    server_public_key = lines_server_public_key[-1]
    
    read_server_private_key = open('/etc/wireguard/server-private.key', 'r')
    lines_server_private_key = read_server_private_key.readlines()
    server_private_key = lines_server_private_key[-1]

    first_time_installation_marker = 0
else:
    print('detected first-time-installation. generating keys and installing qrencode')
    os.system('wg genkey | tee server-private.key | wg pubkey > server-public.key')

    read_server_public_key = open('/etc/wireguard/server-public.key', 'r')
    lines_server_public_key = read_server_public_key.readlines()
    server_public_key = lines_server_public_key[-1]
    
    read_server_private_key = open('/etc/wireguard/server-private.key', 'r')
    lines_server_private_key = read_server_private_key.readlines()
    server_private_key = lines_server_private_key[-1]

    os.system('sudo apt-get install qrencode -y')
    first_time_installation_marker = 1


## check whether the wg0.conf in /etc/wireguard already exists

wgconf = Path('/etc/wireguard/wg0.conf')
if wgconf.is_file():
    print('detected existing wg0.conf')
else:
    print('creating a wg0.conf')
    os.system('wg-quick down wg0')
    print('stopped wireguard')

    wg0_conf = open('wg0.conf', 'w')
    wg0_conf.write('[Interface]\nAddress = ' + str(address_wg0_conf)+ '\nSaveConfig = true\nPostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ' + str(ethernet_port) + ' -j MASQUERADE\nPostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ' + str(ethernet_port) + ' -j MASQUERADE\nListenPort = ' + str(wg_port) + '\nPrivateKey = ' + str(server_private_key) + '\n\n')
    wg0_conf.close()
    os.system('wg-quick up wg0')



total_clients = Path('/etc/wireguard/total_clients.txt')
if total_clients.is_file():
    total_clients_write = open('total_clients.txt', 'a')
    total_clients_read = open('total_clients.txt', 'r')
    line_total_clients = total_clients_read.readlines()
    last_line_total_clients_read = line_total_clients[-1]
    new_client_number = int(last_line_total_clients_read) + 1
    total_clients_write.write(str(new_client_number) + '\n') 
else: 
    total_clients_write = open('total_clients.txt', 'a')
    total_clients_write.write('1\n')
    total_clients_write.close()
    total_clients_read = open('total_clients.txt', 'r')
    line_total_clients = total_clients_read.readlines()
    last_line_total_clients_read = line_total_clients[-1]
    new_client_number = 1


num_lines_total_clients_read = sum(1 for line_total_clients in open('total_clients.txt')) 
## the keys for the new client are being generated
print('creating private and public keys')
os.system('wg genkey | tee ' + clients_conf_file_name + str(new_client_number) + '-private.key | wg pubkey > ' + clients_conf_file_name + str(new_client_number) + ('-public.key'))
## clientx-public.key and clientx-private.key were generated

## the new client keys are being read...
key_open_public = open(clients_conf_file_name + str(new_client_number) + '-public.key', 'r')
key_open_private = open(clients_conf_file_name + str(new_client_number) + '-private.key', 'r')

line_key_open_public = key_open_public.readlines()
line_key_open_private = key_open_private.readlines()

last_line_key_open_public = line_key_open_public[-1]
last_line_key_open_private = line_key_open_private[-1]

## ...and will be pasted into a new .conf together with the interface

second_part_ip_address_client = int(last_bracket_ip_address_client) + (new_client_number - 1)
new_second_part_ip_address_client = str(second_part_ip_address_client) + '/32'
Endpoint = domain + ':' + str(wg_port)

client_conf = open(clients_conf_file_name + str(new_client_number) + '.conf', 'a')



client_conf.write('[Interface]\nAddress = ' + str(first_part_ip_address_client) + str(new_second_part_ip_address_client) + '\nPrivateKey = ' + last_line_key_open_private + 'DNS = ' + str(DNS) + '\n\n[Peer]\nPublicKey = ' + str(server_public_key) + 'Endpoint = ' + str(Endpoint) + '\nAllowedIPs = ' + str(AllowedIPs) + '\n')
print('created a new client.conf')

os.system('wg-quick down wg0')
print('stopped wireguard')
wg0_conf = open('wg0.conf', 'a')
wg0_conf.write('\n[Peer]\nPublicKey = ' + last_line_key_open_public + 'AllowedIPs = ' + str(first_part_ip_address_client) + str(new_second_part_ip_address_client) + '\n\n')
wg0_conf.close()
print('added new client to wg0.conf')

os.system('wg-quick up wg0')

print('wireguard is running with a new client. type sudo cat /etc/wireguard/client' + str(new_client_number) + '.conf | qrencode -t ansiutf8')

## everyting is closed.
total_clients_read.close()
total_clients_write.close()
key_open_public.close()
key_open_private.close()
client_conf.close()

## on first time installation, the autostart is being activated.
if first_time_installation_marker == 1:
    os.system('systemctl enable wg-quick@wg0')
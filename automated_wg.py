from pathlib import Path
import os


def read_last_line(path: str) -> str:
    """Return the last line of a file."""
    with open(path, 'r') as file:
        lines = file.readlines()
    return lines[-1]


def write_text(path: str, content: str) -> None:
    """Write the given content to the specified file."""
    with open(path, 'w') as file:
        file.write(content)


def append_text(path: str, content: str) -> None:
    """Append the given content to the specified file."""
    with open(path, 'a') as file:
        file.write(content)


def run_cmd(command: str) -> None:
    """Execute a system command."""
    os.system(command)


def initialize_server_keys() -> tuple[str, str, int]:
    """
    Check if server key files exist.
    If not, generate them and perform installation steps.
    Returns: (public_key, private_key, first_time_install_marker)
    """
    pub_keyfile = Path('/etc/wireguard/server-public.key')
    priv_keyfile = Path('/etc/wireguard/server-private.key')

    if pub_keyfile.is_file() and priv_keyfile.is_file():
        print('---Welcome to the AutomatedWireGuard-Script---\nNow creating a new Client...')
        return (
            read_last_line(str(pub_keyfile)),
            read_last_line(str(priv_keyfile)),
            0
        )

    print(
        '---Welcome to the AutomatedWireGuard-Script---\n'
        'It will help you install a fully working WireGuard-Server.\n'
        'The total number of existing clients is saved in /etc/wireguard/total_clients.txt and\n'
        'the variables of the first-time-installation are stored in /etc/wireguard/variables.txt.\n'
        'If you want to change these variables, delete variables.txt.\n'
        'Detected first time installation. Installing updates, WireGuard, generating keys and installing qrencode...'
    )

    if input('Do you want to update and upgrade your system? (y/n) ') == 'y':
        run_cmd('apt-get update -y && apt-get upgrade -y')

    if input('Do you want to install Wireguard now? (y/n) ') == 'y':
        run_cmd('apt-get install wireguard -y')
        run_cmd("perl -pi -e 's/#{1,}?net.ipv4.ip_forward ?= ?(0|1)/net.ipv4.ip_forward = 1/g' /etc/sysctl.conf")

    run_cmd('wg genkey | tee /etc/wireguard/server-private.key | wg pubkey > /etc/wireguard/server-public.key')

    pub_key = read_last_line('/etc/wireguard/server-public.key')
    priv_key = read_last_line('/etc/wireguard/server-private.key')

    run_cmd('apt-get install qrencode -y')

    return pub_key, priv_key, 1


def load_or_create_variables(first_time_install: int):
    """
    Load existing variables from variables.txt,
    or prompt the user to create them on first-time setup.
    """
    var_path = Path('/etc/wireguard/variables.txt')
    if first_time_install == 0 and var_path.is_file():
        with open(var_path, 'r') as file:
            line = file.readlines()[-1]
        items = line.split(';')
        return items[-8], items[-7], items[-6], items[-5], items[-4], items[-3], items[-2], items[-1]

    # Prompt user for variables during initial setup
    clients_conf_file_name = input('Client config filename prefix (default: client): ') or 'client'
    first_ip = input('First client IPv4 (default: 10.10.100.2): ') or '10.10.100.2'
    allowed_ips = input('Allowed IP ranges (default: 0.0.0.0/0, ::/0): ') or '0.0.0.0/0, ::/0'
    server_ip = input('Server WireGuard IP (default: 100.64.0.1/24): ') or '100.64.0.1/24'

    run_cmd('ip addr')
    eth_port = input('Ethernet port for outgoing traffic (default: eth0): ') or 'eth0'
    wg_port = input('WireGuard port (default: 51900): ') or '51900'
    dns = input('Client DNS (default: 1.0.0.1): ') or '1.0.0.1'
    domain = input('Domain name for WireGuard endpoint: ')

    write_text(
        str(var_path),
        ';'.join([clients_conf_file_name, first_ip, allowed_ips, server_ip, eth_port, wg_port, dns, domain])
    )

    return clients_conf_file_name, first_ip, allowed_ips, server_ip, eth_port, wg_port, dns, domain


def ensure_wg0_conf(server_private_key: str, address: str, ethernet_port: str, wg_port: str):
    """Create wg0.conf if not already present."""
    conf_path = Path('/etc/wireguard/wg0.conf')

    if conf_path.is_file():
        print('Detected existing wg0.conf')
        return

    print('Creating wg0.conf')
    content = (
        f"[Interface]\n"
        f"Address = {address}\n"
        f"SaveConfig = true\n"
        f"PostUp = iptables -A FORWARD -i %i -j ACCEPT; "
        f"iptables -A FORWARD -o %i -j ACCEPT; "
        f"iptables -t nat -A POSTROUTING -o {ethernet_port} -j MASQUERADE\n"
        f"PostDown = iptables -D FORWARD -i %i -j ACCEPT; "
        f"iptables -D FORWARD -o %i -j ACCEPT; "
        f"iptables -t nat -D POSTROUTING -o {ethernet_port} -j MASQUERADE\n"
        f"ListenPort = {wg_port}\n"
        f"PrivateKey = {server_private_key}\n\n"
    )
    write_text(str(conf_path), content)


def get_new_client_number() -> int:
    """
    Read or create total_clients.txt and return the new client number.
    """
    path = Path('/etc/wireguard/total_clients.txt')

    if not path.is_file():
        write_text(str(path), '1\n')
        return 1

    with open(path, 'r') as file:
        last = int(file.readlines()[-1])

    append_text(str(path), f"{last + 1}\n")
    return last + 1


def create_client_config(client_prefix, number, first_ip, allowed_ips, dns, domain, wg_port, server_pub_key):
    """Generate keys and create client configuration."""
    priv = f"/etc/wireguard/{client_prefix}{number}-private.key"
    pub = f"/etc/wireguard/{client_prefix}{number}-public.key"

    run_cmd(f"wg genkey | tee {priv} | wg pubkey > {pub}")

    pub_key = read_last_line(pub)
    priv_key = read_last_line(priv)

    base_ip = ".".join(first_ip.split(".")[:3]) + "."
    offset = int(first_ip.split('.')[-1]) + (number - 1)
    new_ip = f"{base_ip}{offset}/32"
    endpoint = f"{domain}:{wg_port}"

    conf_path = f"/etc/wireguard/{client_prefix}{number}.conf"

    content = (
        f"[Interface]\n"
        f"Address = {new_ip}\n"
        f"PrivateKey = {priv_key}"
        f"DNS = {dns}\n\n"
        f"[Peer]\n"
        f"PublicKey = {server_pub_key}"
        f"Endpoint = {endpoint}\n"
        f"AllowedIPs = {allowed_ips}\n"
    )

    write_text(conf_path, content)
    return new_ip, pub_key


def append_peer_to_server_conf(client_public_key: str, client_ip: str):
    """Append a new peer configuration to wg0.conf."""
    append_text('/etc/wireguard/wg0.conf',
        f"\n[Peer]\nPublicKey = {client_public_key}"
        f"AllowedIPs = {client_ip}\n\n"
    )


def generate_qr(client_prefix: str, number: int):
    """Generate and display QR code for the client config."""
    cfg = f"/etc/wireguard/{client_prefix}{number}.conf"
    run_cmd(f"cat {cfg} | qrencode -t ansiutf8")
    run_cmd(f"cat {cfg} | qrencode -t png -o {cfg[:-5]}-qr.png")


def main():
    os.system('ls')

    server_pub, server_priv, first_install = initialize_server_keys()

    vars_loaded = load_or_create_variables(first_install)
    (client_prefix, first_ip, allowed_ips, address, eth_port, wg_port, dns, domain) = vars_loaded

    ensure_wg0_conf(server_priv, address, eth_port, wg_port)

    client_number = get_new_client_number()

    print('Creating private and public keys...')
    client_ip, client_pub_key = create_client_config(
        client_prefix, client_number, first_ip, allowed_ips, dns, domain, wg_port, server_pub
    )

    print('Adding new client to wg0.conf')
    if first_install != 1:
        run_cmd('wg-quick down wg0')

    append_peer_to_server_conf(client_pub_key, client_ip)

    if first_install != 1:
        run_cmd('wg-quick up wg0')

    print(f'Client config created: /etc/wireguard/{client_prefix}{client_number}.conf')

    generate_qr(client_prefix, client_number)

    if first_install == 1:
        print(
            f'WireGuard installed with first client. QR saved as /etc/wireguard/{client_prefix}{client_number}-qr.png.\n'
            'Reboot is required before first use.'
        )
    else:
        print(
            f'WireGuard running with a new client. QR saved as /etc/wireguard/{client_prefix}{client_number}-qr.png.'
        )

    run_cmd('chown -R root:root /etc/wireguard/ && chmod -R og-rwx /etc/wireguard/*')

    if first_install == 1:
        if input('Do you want to reboot now? (y/n) ') == 'y':
            run_cmd('reboot now')


if __name__ == "__main__":
    main()

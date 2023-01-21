""" 
Developed by AVCDO
> Only for practise, do not use really
> Only shows you packets with ip header
"""

from platform import system
from argparse import ArgumentParser
from socket import socket, inet_ntoa, ntohs, ntohl, AF_INET, SOCK_RAW, IPPROTO_IP, INADDR_ANY
from struct import unpack, pack

# format string, default header size
IP_PACKET = '!BBHHHBBHII', 20
TCP_PACKET = '!HHIIHHHH', 20
UDP_PACKET = '!IIBBHHHHH', 20

display_db = {
    'flags': {
        0: 'unset',
        1: 'FIN', 2: 'SYN', 4: 'RST',
        8: 'PSH', 16: 'ACK', 32: 'URG',
        64: 'ECE', 128: 'CWR', 256: 'NS',
    },
    'protocols':{
        6: 'TCP', 17: 'UDP'
    }
}

class colors:
    def __init__(self) -> None:
        if self.__check_sys():
            self.__fix_colors_windows()

        self.RESET = '\033[0m'
        self.RED = '\033[31m'
        self.GREEN = '\033[32m'
        self.BLUE = '\033[34m'
        self.CYAN = '\033[36m'
    
    def __fix_colors_windows(self) -> None:
        """Fixing colors for windows."""
        kernel32 = __import__('ctypes').WinDLL('kernel32')
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        del kernel32
    
    def __check_sys(self) -> bool:
        """Check for system."""
        ops = system()
        if ops == 'Windows': del ops; return True
        elif ops == 'Linux': del ops; return False
        else: del ops; return None

def handle_args() -> dict:
    """Get parsed args as dictionary."""
    args = {}
    default = (0, )
    p = ArgumentParser(
        prog='packet sniffer',
        description='Packet sniffer | only for practise',
        epilog='Developed by AVCDO'
    )
    p.add_argument('-m', '--mode')

    for idx, arg in enumerate(p.parse_args()._get_kwargs()): # convert kwargs to dict
        args.update({arg[0]: arg[1] if arg[1] is not None else default[idx]})
    return args

color = colors()
args = handle_args()

def display(ip_content: dict, proto_content: dict) -> None:
    """Display packet data in console."""
    mode = int(args.get('mode'))
    match mode:
        case 0:
            match ip_content['protocol']:
                case 6:
                    print(f' > [{color.CYAN}{display_db["protocols"][ip_content["protocol"]]}{color.RESET}] {color.BLUE}{ip_content["src_ip"]}{color.RESET} -{color.GREEN}{display_db["flags"][proto_content["flag"]] if display_db["flags"][proto_content["flag"]] != "unset" else ""}{color.RESET}-> {color.BLUE}{ip_content["dest_ip"]}{color.RESET} {color.RED}TTL={ip_content["ttl"]}')
                case 17:
                    print(f' > [{color.CYAN}{display_db["protocols"][ip_content["protocol"]]}{color.RESET}] {color.BLUE}{ip_content["src_ip"]}{color.RESET} --> {color.BLUE}{ip_content["dest_ip"]}{color.RESET} {color.RED}TTL={ip_content["ttl"]}')
        case 1:
            match ip_content['protocol']:
                case 6:
                    print(f''' > [{color.CYAN}{display_db["protocols"][ip_content["protocol"]]}{color.RESET}] {color.BLUE}{ip_content["src_ip"]}{color.RESET} -{color.GREEN}{display_db["flags"][proto_content["flag"]] if display_db["flags"][proto_content["flag"]] != "unset" else ""}{color.RESET}-> {color.BLUE}{ip_content["dest_ip"]}{color.RESET} {color.RED}TTL={ip_content["ttl"]}
   {f"{color.CYAN}options:{color.RED} {proto_content['options']}{color.RESET}" if proto_content['optlength'] else ""}\n   {color.CYAN}Source Port:{color.RED} {proto_content['src_port']}{color.RESET}\n   {color.CYAN}Destination Port:{color.RED} {proto_content['dest_port']}{color.RESET}\n''')
                case 17:
                    print(f''' > [{color.CYAN}{display_db["protocols"][ip_content["protocol"]]}{color.RESET}] {color.BLUE}{ip_content["src_ip"]}{color.RESET} -> {color.BLUE}{ip_content["dest_ip"]}{color.RESET} {color.RED}TTL={ip_content["ttl"]}
   {color.CYAN}Quell IP:{color.RED} {proto_content['quell_ip']}{color.RESET}\n   {color.CYAN}Target IP:{color.RED} {proto_content['target_ip']}{color.RESET}\n   {color.CYAN}Protocol ID:{color.RED} {proto_content['proto_id']}{color.RESET}\n''')

def readable_ip(intIP) -> str:
    """Convert unpacked integer ip address to readable string."""
    return inet_ntoa(pack('!I', intIP))

def tcp(payload: bytes) -> dict:
    """Extract informations of the tcp header."""
    header = unpack(TCP_PACKET[0], payload[:TCP_PACKET[1]])
    data = {
        'src_port':     ntohs(header[0]),
        'dest_port':    ntohs(header[1]),
        'seq_num':      ntohl(header[2]),
        'ack_num':      ntohl(header[3]),
        'win_size':     ntohs(header[5]),
        'data_offset':  ((header[6] >> 4) & 0xF) * 4,
        'flag':         header[6] & 0x0002,
        'urg':          ntohs(header[7]),
        'optlength':    0,
        'options':      None
    }
    # reassign None values
    if data['data_offset'] > 20:
        data['optlength'] = data['data_offset'] - TCP_PACKET[1]
        data['options'] = payload[TCP_PACKET[1]: data['data_offset']]
    return data

def udp(payload: bytes) -> dict:
    """Extract informations of the udp header."""
    header = unpack(UDP_PACKET[0], payload[:UDP_PACKET[1]])
    data = {
        'quell_ip':     readable_ip(header[0]),
        'target_ip':    readable_ip(header[1]),
        'proto_id':     header[3],
        'length':       ntohs(header[4])
    }
    return data

def extract_ip_information(packet: bytes) -> dict:
    """Get all important information from the ip header."""
    header = unpack(IP_PACKET[0], packet[:IP_PACKET[1]])
    data = {
        'header_length':    (header[0] & 0xF) * 4,
        'total_length':     header[2],
        'ttl':              header[5],
        'protocol':         header[6],
        'src_ip':           readable_ip(header[8]),
        'dest_ip':          readable_ip(header[9]),
        'optlength':        0,
        'optsec':          None
    }
    # handle options
    if data['header_length'] > 5:
        data['optlength'] = data['header_length'] - IP_PACKET[1]
        data['optsec'] = packet[data['header_length']: data['header_length'] + data['optlength']]
    return data

def extract_protocol_header(protocol: int, payload: bytes) -> dict:
    """Get all important informations about the protocol header in the payload."""
    match protocol:
        case 6: return tcp(payload)
        case 17: return udp(payload)
        case _: raise Exception('Protocol isn\'t available')
    
def process_packet(packet: bytes) -> None:
    """Unpack data of packets."""
    ip_data = extract_ip_information(packet)
    payload = packet[ip_data['header_length'] + ip_data['optlength']: ip_data['total_length']]
    proto_data = extract_protocol_header(ip_data['protocol'], payload)
    display(ip_data, proto_data)

def main() -> None:
    """Start sniffing."""
    s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
    s.bind(('0.0.0.0', INADDR_ANY))
    print(f'{color.GREEN}Start sniffing...\n{color.RESET}')
    while True:
        packet = s.recvfrom(65565)[0]
        process_packet(packet)
        

if __name__ == '__main__':
    main()

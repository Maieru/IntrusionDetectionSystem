import socket
import struct
import subprocess
import time

# Cria um socket raw
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

# Define a interface de rede para escutar
s.bind(('enp0s3', 0))

syn_count = {}
ipsBloqueados = set()
syn_timestamps = {}

def listar_ips_bloqueados():
    result = subprocess.run(["sudo", "iptables", "-L", "-n", "-v"], capture_output=True, text=True)
    print(result.stdout)

def log_ip_bloqueado(ip):
    with open("ips_bloqueados.log", "a") as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - IP bloqueado: {ip}\n")

def limpar_iptables():
    subprocess.run(["sudo", "iptables", "-F"])
    print("Todas as regras do iptables foram limpas.")

# Recebe pacotes em um loop
while True:
    packet = s.recvfrom(65565)[0]
    
    #print("Pacote recebido")
    # O cabeçalho Ethernet tem 14 bytes
    eth_length = 14

    # Pula o cabeçalho Ethernet
    eth_header = packet[:eth_length]
    eth = struct.unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])
    #print("Protocolo Ethernet: {}".format(eth_protocol))    

    if eth_protocol == 8:
        #print("Pacote IP detectado")
        # O cabeçalho IP tem 20 bytes
        ip_header = packet[eth_length:eth_length + 20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        protocol = iph[6]

        # Verifica se o protocolo é TCP (6)
        if protocol == 6:
            #print("Pacote TCP detectado")
            # O cabeçalho TCP começa após o cabeçalho IP
            iph_length = (iph[0] & 0xF) * 4
            tcp_header_start = eth_length + iph_length
            tcp_header = packet[tcp_header_start:tcp_header_start + 20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            flags = tcph[5]

            # Verifica se o bit SYN está definido (0x02)
            if flags & 0x02:
                
                s_addr = socket.inet_ntoa(iph[8])
                current_time = time.time()
                
                if s_addr in syn_timestamps:
                    syn_timestamps[s_addr].append(current_time)
                else:
                    syn_timestamps[s_addr] = [current_time]

                if s_addr in ipsBloqueados:
                    continue

                # Remove timestamps mais antigos que 1 segundo
                syn_timestamps[s_addr] = [timestamp for timestamp in syn_timestamps[s_addr] if current_time - timestamp <= 1]

                print(f"Número de pacotes SYN de {s_addr} no último segundo: {len(syn_timestamps[s_addr])}")

                if len(syn_timestamps[s_addr]) > 3:
                    print('Ataque SYN detectado')
                    if s_addr not in ipsBloqueados:
                        ipsBloqueados.add(s_addr)
                        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", s_addr, "-j", "DROP"])
                        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "icmp", "-s", s_addr, "-j", "DROP"])
                        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "-s", s_addr, "-j", "DROP"])
                        subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-s", s_addr, "-j", "DROP"])
                        subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-p", "icmp", "-s", s_addr, "-j", "DROP"])
                        subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-p", "tcp", "-s", s_addr, "-j", "DROP"])

                        log_ip_bloqueado(s_addr)
                        print("IP bloqueado pelo iptables: {}".format(s_addr))
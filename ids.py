import socket
import struct
import subprocess

# Cria um socket raw
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

# Define a interface de rede para escutar
s.bind(('lo', 0))

syn_count = {}
ipsBloqueados = set()

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
                #print("Pacote SYN detectado")
                
                s_addr = socket.inet_ntoa(iph[8])
                
                if s_addr in syn_count:
                    syn_count[s_addr] += 1
                else:
                    syn_count[s_addr] = 1

                print(f"Número de pacotes SYN de {s_addr}: {syn_count[s_addr]}")

                if syn_count[s_addr] > 5:
                    print('Ataque SYN detectado')
                    if s_addr not in ipsBloqueados:
                        ipsBloqueados.add(s_addr)
                        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", s_addr, "-j", "DROP"])
                        print("IP bloqueado pelo iptables: {}".format(s_addr))
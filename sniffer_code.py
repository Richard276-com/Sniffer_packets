import socket

def scomposizione_pacchetto_MAC(raw_data):
    dest_mac = raw_data[0:6]
    src_mac = raw_data[6:12]
    tipo = raw_data[12:14]
    dati = raw_data[14:]

    print(f"Indirizzo MAC di destinazione: {dest_mac.hex(':')}")
    print(f"Indirizzo MAC di origine: {src_mac.hex(':')}")
    print(f"Tipo: {tipo.hex()}")
    print(f"Dati: {dati.hex()}")

    return dest_mac, src_mac, tipo, dati

def scomposizione_pacchetto_IP(dati):
    if len(dati) < 20:
        print("Pacchetto IP troppo corto")
        return

    primo_byte = dati[0]
    versione = primo_byte >> 4          
    ihl = primo_byte & 0x0F             
    lunghezza_header = ihl * 4          
    tipo_servizio = dati[1]            
    lunghezza_totale = dati[2:4]       
    identificativo = dati[4:6]          

    sesto_settimo = int.from_bytes(dati[6:8], byteorder='big')
    flags = sesto_settimo >> 13                    
    fragment_offset = sesto_settimo & 0x1FFF       

    ttl = dati[8]                       
    protocollo = dati[9]                
    header_checksum = dati[10:12]       
    src_ip = dati[12:16]                
    dest_ip = dati[16:20]               
    payload = dati[lunghezza_header:]   

    print(f"Versione: {versione}")
    print(f"Lunghezza header: {lunghezza_header} byte")
    print(f"Tipo di servizio: {tipo_servizio}")
    print(f"Lunghezza totale: {int.from_bytes(lunghezza_totale, 'big')}")
    print(f"Identificativo: {identificativo.hex()}")
    print(f"Flags: {flags:03b}") 
    print(f"Fragment offset: {fragment_offset}")
    print(f"TTL: {ttl}")
    print(f"Protocollo: {protocollo}")
    print(f"Header checksum: {header_checksum.hex()}")
    print(f"Indirizzo IP di origine: {socket.inet_ntoa(src_ip)}")
    print(f"Indirizzo IP di destinazione: {socket.inet_ntoa(dest_ip)}")
    print(f"Dati: {payload.hex()}")

def main():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    print("Sniffer avviato, in attesa di pacchetti...")

    for i in range(5):
        raw_data, addr = sock.recvfrom(65535)
        print(f"Pacchetto catturato: {len(raw_data)} byte")
        dest_mac, src_mac, tipo, dati = scomposizione_pacchetto_MAC(raw_data)

        tipo_numeri = int.from_bytes(tipo, byteorder='big')
        if tipo_numeri == 0x0800:
            scomposizione_pacchetto_IP(dati)
        else:
            print("Pacchetto non di tipo IPv4!")

if __name__ == '__main__':
    main()
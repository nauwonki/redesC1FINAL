import socket
from dnslib import DNSRecord
from dnslib.dns import CLASS, QTYPE

def parse_dns_message(message):
    d = DNSRecord.parse(message)
    return {
        "Qname": str(d.get_q().get_qname()),
        "ANCOUNT": d.header.a,
        "NSCOUNT": d.header.auth,
        "ARCOUNT": d.header.ar,
        "Answer": [
            {
                "NAME": str(rr.rname),
                "TYPE": QTYPE.get(rr.rtype),
                "CLASS": CLASS.get(rr.rclass),
                "TTL": rr.ttl,
                "RDATA": str(rr.rdata),
            }
            for rr in d.rr
        ],
        "Authority": [
            {
                "NAME": str(rr.rname),
                "TYPE": QTYPE.get(rr.rtype),
                "CLASS": CLASS.get(rr.rclass),
                "TTL": rr.ttl,
                "RDATA": str(rr.rdata),
            }
            for rr in d.auth
        ],
        "Additional": [
            {
                "NAME": str(rr.rname),
                "TYPE": QTYPE.get(rr.rtype),
                "CLASS": CLASS.get(rr.rclass),
                "TTL": rr.ttl,
                "RDATA": str(rr.rdata),
            }
            for rr in d.ar
        ]
    }

historial = []
cache = {}
def get_last_3():
    conteo = {}
    for dom in historial:
        conteo[dom] = conteo.get(dom, 0) + 1

    ordenado = sorted(conteo.items(), key=lambda x: x[1], reverse=True)
    return [dom for dom, _ in ordenado[:3]]

def refresh_history(qname):
    global historial, cache
    historial.append(qname)
    if len(historial) > 20:
        historial.pop(0)
    
    top3 = get_last_3()
    cache = {k: v for k, v in cache.items() if k in top3}

def put_in_cache(qname, response):
    if qname in get_last_3():
        cache[qname] = response

root_ip = "198.41.0.4"
def resolver(mensaje_consulta: bytes, ip_ddr=root_ip, ns_name=".") -> bytes:
    parsed = parse_dns_message(mensaje_consulta)
    qname = parsed["Qname"]

    refresh_history(qname)

    if qname in cache:
        print(f"(debug) Cache Consultando '{qname}' ns_name: {ns_name} direccion IP: {ip_ddr}")
        d_cache = DNSRecord.parse(cache[qname])
        d_cache.header.id = DNSRecord.parse(mensaje_consulta).header.id
        return bytes(d_cache.pack())

    print(f"(debug) Consultando '{qname}' a '{ns_name}' con direccion IP '{ip_ddr}'")
    
    server_address = (ip_ddr, 53)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(mensaje_consulta, server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    
    d = parse_dns_message(data)
    
    tipo_a = any(record["TYPE"] == "A" for record in d["Answer"])
    if tipo_a:
        put_in_cache(qname, data)
        return data
    
    tipo_ns = any(record["TYPE"] == "NS" for record in d["Authority"])
    if tipo_ns:
        nuevo_ns = None
        for record in d["Authority"]:
            if record["TYPE"] == "NS":
                nuevo_ns = record["RDATA"]
                break
        
        nuevo_ip = None
        for record in d["Additional"]:
            if record["TYPE"] == "A":
                nuevo_ip = record["RDATA"]
                break
        if nuevo_ip:
            res = resolver(mensaje_consulta, ip_ddr=nuevo_ip, ns_name=nuevo_ns) 
            if res:
                put_in_cache(qname, res)
            return res
        else:
            if nuevo_ns:
                ns_bytes = bytes(DNSRecord.question(nuevo_ns).pack())
                response_ns = resolver(ns_bytes, ip_ddr=root_ip, ns_name=".")
                d2 = parse_dns_message(response_ns)

                ns_ip = None
                for record in d2["Answer"]:
                    if record["TYPE"] == "A":
                        ns_ip = record["RDATA"]
                        break
                if ns_ip:
                    res2 = resolver(mensaje_consulta, ip_ddr=ns_ip, ns_name=nuevo_ns)
                    if res2:
                        put_in_cache(qname, res2)
                    return res2
    return data

if __name__ == "__main__":
    buff_size = 4096
    new_socket_address = ("192.168.64.2", 8000)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(new_socket_address)
    print(f"DNS escuchando en {new_socket_address}")
    while True:
        message, address = server_socket.recvfrom(buff_size)
        
        print(f"Mensaje: {message}")
        parsed_message = parse_dns_message(message)
        print("Mensaje parseado:")
        print(parsed_message)

        resolve = resolver(message, root_ip)

        if resolve:
            server_socket.sendto(resolve, address)
            print(f"Respuesta enviada a {address}")
        else:
            print("Vacio")


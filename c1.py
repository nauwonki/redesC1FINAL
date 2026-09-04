import socket 

#Parsear mensaje HTTP
def parse_HTTP_message(http_message: bytes):
    #Separar Head y Body spliteando en \r\n\r\n
    separate = http_message.split(b"\r\n\r\n")
    #Definir Head y Body, decodificando el head
    head = separate[0].decode()
    body = separate[1]

    #Separar los headers y definir el start line
    header = head.split("\r\n")
    start_line = header[0]

    #Parsear start line
    start_line_parts = start_line.split(" ", 2)
    message = None
    start_line_parsed = {}

    if (start_line_parts[0].startswith("HTTP/")):
        #Es un response
        message = "Response"
        start_line_parsed["version"] = start_line_parts[0]
        start_line_parsed["codigo"] = start_line_parts[1]
        start_line_parsed["texto"] = start_line_parts[2]
    else:
        #Es un request
        message = "Request"
        start_line_parsed["metodo"] = start_line_parts[0]
        start_line_parsed["direccion"] = start_line_parts[1]
        start_line_parsed["version"] = start_line_parts[2]

    #Headers restantes
    headers = [line for line in header[1:] if line]

    return {
        "tipo": message,
        "start_line": start_line_parsed,
        "headers": headers,
        "body": body
    }


def create_HTTP_message(parsed_message):
    #Identificar startline, headers y body
    start_line_parsed = parsed_message["start_line"]
    headers = parsed_message["headers"]
    body = parsed_message["body"]

    #Identificar starline dependiendo del tipo del mensaje
    if parsed_message["tipo"] == "Request":
        start_line = f"{start_line_parsed['metodo']} {start_line_parsed['direccion']} {start_line_parsed['version']}"
    else:
        start_line = f"{start_line_parsed['version']} {start_line_parsed['codigo']} {start_line_parsed['texto']}"

    body_to_bytes = body

    #Construir headers
    header_lines = [start_line]
    for h in headers:
        header_lines.append(h)

    #Unir head y pasar a bytes
    head_to_bytes = ("\r\n".join(header_lines) + "\r\n\r\n").encode()

    #Unir head y body
    return head_to_bytes + body_to_bytes

def get_content_length(header):
    head = header.decode()
    for i in head.split("\r\n"):
        if i.lower().startswith("content-length:"):
            return int(i.split(":", 1)[1].strip())
    return None

#Socket servidor tcp
def receive_full_message(connection_socket, buff_size, end_sequence):
    full_message = b""

    while end_sequence not in full_message:
        c = connection_socket.recv(buff_size)
        if len(c) == 0:
            return full_message
        full_message += c

    head, _, body = full_message.partition(end_sequence)

    content_length = get_content_length(head)
    body_rec = len(body)

    while content_length is not None and body_rec < content_length:
        c = connection_socket.recv(buff_size)
        if len(c) == 0:
            break
        full_message += c
        body_rec += len(c)

    return full_message
    

def get_destination(parsed_request):
    host = None
    port = 80

    for h in parsed_request["headers"]:
        if h.lower().startswith("host:"):
            host_val = h.split(":", 1)[1].strip()
            if ":" in host_val:
                host, port_str = host_val.split(":")
                port = int(port_str)
            else:
                host = host_val
            break
    return host, port

def find_bracket(content, start, open, close):
    d = 0
    for i in range(start, len(content)):
        if content[i] == open:
            d += 1
        elif content[i] == close:
            d -= 1
            if d == 0:
                return i
    return -1

def load_blocked_sites(filename="config.json"):
    block = []
    username = "Nahuel Won"
    forbidden = []

    with open(filename, "r") as f:
        c = f.read()
        if '"user' in c:
            separate_user = c.split('"user"', 1)[1].split(",", 1)[0]
            username = separate_user.split(":", 1)[1].strip().strip('"').strip("'")
        
        if "blocked" in c:
            separate_block = c.split('"blocked"', 1)[1].split("]", 1)[0]
            i = separate_block.split("[", 1)[-1].split(",")
            for item in i:
                stripped = item.strip().strip('""').strip("'").strip()
                if stripped:
                    block.append(stripped)

        if '"forbidden_words"' in c:
            d = c.find('"forbidden_words"')
            start = c.find("[", d)
            end = find_bracket(c, start, "[", "]")
            separate_words = c[start + 1:end]
            
            i = 0
            while True:
                starts = separate_words.find("{", i)
                if starts == -1:
                    break
                ends = find_bracket(separate_words, starts, "{", "}")
                if ends == -1:
                    break
                s = separate_words[starts + 1:ends].strip()
                if ":" in s:
                    k, v = s.split(":", 1)
                    k_clean = k.strip().strip('"').strip("'")
                    v_clean = v.strip().strip('"').strip("'")
                    if k_clean:
                        forbidden.append((k_clean, v_clean))
                i = ends + 1

    return username, block, forbidden

def is_blocked(parsed_request, blocked):
    host, _ = get_destination(parsed_request)
    path = parsed_request["start_line"].get("direccion", "")
    url = f"{host}{path}" if host else path

    for b in blocked:
        c = b.replace("http://", "")
        if c in url or (host and c in host):
            return True
    return False

def response_403():
    html = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>403 Forbidden</title>
</head>
<body>
    <h1>403 Forbidden - Acceso Denegado</h1>
    <p>El sitio web al que intentas acceder está bloqueado por el Proxy.</p>
    <img src="/gato.jpg" alt="Sitio Bloqueado">
</body>
</html>"""
    body = html.encode()
    res = [
        "HTTP/1.1 403 Forbidden",
        "Content-Type: text/html",
        f"Content-length: {len(body)}",
        "Connection: close"
    ]
    headers = "\r\n".join(res) + "\r\n\r\n"
    return headers.encode() + body

def build_image(image="gato.jpg"):
    with open(image, "rb") as f:
        image_byte = f.read()
    res = [
        "HTTP/1.1 200 OK",
        "Content-Type: image/jpeg",
        f"Content-Length: {len(image_byte)}",
        "Connection: close"
    ]
    headers = "\r\n".join(res) + "\r\n\r\n"
    return headers.encode() + image_byte

def add_header(parsed_request, header):
    parsed_request["headers"].append(header)
    return parsed_request

def replace_forbidden_words(response, forbidden_words):
    if b"\r\n\r\n" not in response:
        return response
    
    headers, body = response.split(b"\r\n\r\n")

    body_text = body.decode()
    for w, replacement in forbidden_words:
        body_text = body_text.replace(w, replacement)
    new_body = body_text.encode()

    header_lines = headers.decode().split("\r\n")
    new_header_lines = []

    for l in header_lines:
        if l.lower().startswith("content-length:"):
            new_header_lines.append(f"Content-length: {len(new_body)}")
        else:
            new_header_lines.append(l)
    
    new_header = "\r\n".join(new_header_lines) + "\r\n\r\n"
    return new_header.encode() + new_body
            
if __name__ == "__main__":
    mi_nombre, blocked, forbidden_words = load_blocked_sites("config.json")
    buff_size = 4096
    end_of_message = b"\r\n\r\n"
    new_socket_address = ('192.168.64.2', 8000)

    print('Creando socket - Proxy')
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.bind(new_socket_address)
    server_socket.listen(5)

    print('... Esperando clientes')
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Conexion desde: {client_address}")
        client_request = receive_full_message(client_socket, buff_size, end_of_message)

        if len(client_request) > 0:
            print("ejecutando parse HTTP")
            #Al recibir mensaje, parsearlo
            parsed_request = parse_HTTP_message(client_request)
            path = parsed_request["start_line"].get("direccion", "")
            
            if path.endswith("gato.jpg"):
                print("peticion recibida imagen gato")
                client_socket.send(build_image("gato.jpg"))
            elif is_blocked(parsed_request, blocked):
                print("sitio bloqueado")
                client_socket.send(response_403())
            else:
                host, port = get_destination(parsed_request)
                print(f"destino: {host}:{port}")

                parsed_request_header = add_header(parsed_request, f"X-ElQuePregunta: {mi_nombre}")
                send_request = create_HTTP_message(parsed_request_header)

                dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                dest_socket.connect((host, port))
                dest_socket.send(send_request)
                server_res = receive_full_message(dest_socket, buff_size, end_of_message)
                replace_res = replace_forbidden_words(server_res, forbidden_words)
                client_socket.send(replace_res)
                dest_socket.close()
               
        client_socket.close()
        print(f"conexion con {client_address} ha sido cerrada")
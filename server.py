import socket
# Make a new socket object.
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


server_address = ("127.0.0.1", 45002)

server_socket.bind(server_address)
print("[SERVER] Socket info:", server_socket)
print("[SERVER] Waiting...")
# This line of code will "Block" the execution of the program.
packet = server_socket.recvfrom(4096)
data, client_address = packet
print("[SERVER] IN", data)

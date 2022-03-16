import socket

host = socket.gethostbyname('localhost')

port = 8080

s = socket.socket()

s.bind((host, port))

s.listen(1)

c, address = s.accept()

print("Connection from: " + str(address))

while True:
    data = c.recv(1024).decode("utf-8")
    if not data:
        break
    print("From user " + data)
    data = data.upper()
    c.send(data.encode("utf-8"))
c.close()

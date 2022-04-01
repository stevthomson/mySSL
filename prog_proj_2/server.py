import socket
import threading
from myssl import *


PRIVATE_KEY = 'server.key'

''' main method listens for connections and starts new thread to handle each connection '''
def main():
    IP = '0.0.0.0'
    PORT = 9995
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP, PORT))
    server.listen(5)

    print('Waiting for clients to connect on PORT ', PORT)

    while(True):
        #loop for multiple connections
        client, addr = server.accept()
        print('Connection to server made from IP:', addr)
        client_handler = threading.Thread(target = handle_client, args = (client,))
        client_handler.start()


''' client handler works as 3 phase driver '''
def handle_client(client_socket):
    #TODO
    try:
        client_cert, k_ab = handshake(client_socket)
        client_key, client_sign_key, srvr_key, srvr_sign_key = key_exchange(client_socket, client_cert, k_ab)
        sendfile(client_socket, client_key, client_sign_key, srvr_key, srvr_sign_key)
    except RuntimeError as re:
        print(re.args)
    except ValueError as ve:
        print(ve.args)
    except Exception as e:
        print(e.args)


''' handshake phase driver '''
def handshake(client_socket):
    all_msgs = []
    client_hello = recieve(client_socket)
    all_msgs.append(client_hello)
    print('recieved',client_hello.decode('ISO-8859-1'))

    print('sending certificate...')
    cert = read_bytes('server.crt')
    all_msgs.append(cert)
    send(client_socket, cert)

    msg = recieve(client_socket)
    all_msgs.append(msg)
    cipher, r_a, client_cert = split(msg)
    print('recieved certificate from client...')
    validate(client_cert)

    print('recieved cipher:',cipher, '\nr_a:',r_a)
    r_b = get_nonce()
    print('r_b:',r_b)
    enc_nonce = cert_encrypt(r_b.to_bytes(32,'little'), client_cert)
    all_msgs.append(enc_nonce)
    send(client_socket,enc_nonce)

    master_secret = r_a ^ r_b
    print('master secret:', master_secret)
    master_secret = base64.urlsafe_b64encode(master_secret.to_bytes(32, 'little'))
    print('master secret:', master_secret)

    rec_hash = rec_and_comp_hash(all_msgs, master_secret, client_socket)
    all_msgs.append(rec_hash)

    hash = keyed_hash(all_msgs, master_secret, b'SERVER')
    print('new hash to send:', hash)
    send(client_socket, hash)
    return client_cert, master_secret


'''
    exchange of derrived keys phase driver 

    a --------Kb+{k_a2, k_a3, K_a-{k_a2, k_a3}}--------> b
    a <-------Ka+{k_b2, k_b3, K_b-{k_a2, k_a3}}--------- b

    new derrived keys are then tested in test_encryption method
    new keys are derrived as a function of the master secret 
'''
def key_exchange(client_socket, client_cert, k_ab):
    k_a2, k_a3, a_sig = get_keys_sig(recieve(client_socket), k_ab)
    print('recieved server keys...')
    print('verifying server signature')
    verify_sig(client_cert, a_sig, k_a2 + b'\n\n' + k_a3)
    print('signature valid!')

    print('generating keys and sending to client...')

    k_b2, k_b3 = get_new_keys(k_ab)
    print('encryption key:', k_b2)
    print('signing key:', k_b3)

    plain_text = k_b2 + b'\n\n'+ k_b3
    sig = sign(plain_text, PRIVATE_KEY)
    msg = aes_encrypt(plain_text + b'\n\n' + sig, k_ab)
    print('sending encrypted keys and signature to client...')
    send(client_socket, msg)

    test_encryption(client_socket, k_a2, k_a3, k_b2, k_b3)

    return k_a2, k_a3, k_b2, k_b3


''' file sending phase driver 

    a ----------K_b2{filename K_a3{filename}}------> b
    a <--------------K_a2{file data}---------------- b
    a ---------K_b2{recieved, K_a3{received}}------> b
    a <------K_a2{hash{file}, k_b3{hash{file}}}----- b

    client requests filename, server sends file data
    client confirms retrieval of file, then the server sends the hash
    and signature of the hash so the client may verify the file was
    not corrupted in transport. Client then saves the file and the 
    client will close the connection
'''
def sendfile(client_socket, client_key, client_sign_key, srvr_key, srvr_sign_key):
    file_req = aes_decrypt(bytes(recieve(client_socket)), srvr_key)
    file_req = file_req.split(b'\n\n', 1)
    sig = file_req[1]
    path = file_req[0]

    aes_validate_sig(path, client_sign_key, sig)

    print('client requested', path.decode())

    fullpath = 'serverfiles/' + path.decode()

    file = read_bytes(fullpath)

    print('sending file...')
    send(client_socket, aes_encrypt(file, client_key))

    recv = aes_decrypt(bytes(recieve(client_socket)), srvr_key)
    recv = recv.split(b'\n\n', 1)
    sig = recv[1]
    recv = recv[0]
    aes_validate_sig(recv, client_sign_key, sig)

    print('recieved file download confirmation...')

    hashcode = hashlib.md5(file).digest()
    sig = aes_sign(hashcode, srvr_sign_key)

    print('sending hash of original file...')
    send(client_socket, aes_encrypt(hashcode + b'\n\n' + sig, client_key))

    print('complete!')


'''splits message into each part for use'''
def split(msg):
    msg = msg.decode('ISO-8859-1')
    msg = msg.split('\n\n', 2)
    cipher = msg[0]
    enc_nonce = msg[1]
    cert_data = msg[2]
    client_cert = get_cert(cert_data.encode('ISO-8859-1'))
    r_a = cert_decrypt(enc_nonce.encode('ISO-8859-1'), PRIVATE_KEY)
    r_a = int.from_bytes(r_a, 'little')
    return cipher, r_a, client_cert


'''recieve and compare HMAC'''
def rec_and_comp_hash(all_msgs, master_secret, client_socket):
    comp = keyed_hash(all_msgs, master_secret, b'CLIENT')
    print('reference hash:',comp)
    rec_hash = bytes(recieve(client_socket))
    print('recieved hash:',rec_hash)
    compare_hashes(comp, rec_hash)
    return rec_hash


''' 
    after key exchange server and client engage in the following protocol:
    a --------------Kb2{r_a2, Ka3(r_a2))--------------> b
    a <-----------Ka2(r_a2 + 1, Kb3(r_a+1))------------ b
    they use their keys exchanged to encrypt, decrypt, sign and verify
    to ensure the keys are working
'''
def test_encryption(client_socket, k_a2, k_a3, k_b2, k_b3):
    print('testing encryption...')
    test = aes_decrypt(bytes(recieve(client_socket)), k_b2)
    print('recieved challenge...')
    test = test.split(b'\n\n', 1)
    num = test[0]
    sig = test[1]
    print('sig:',sig)
    print('verifiying signature...')
    aes_validate_sig(num, k_a3, sig)
    r_a2 = int.from_bytes(num, 'little')
    num = r_a2 + 1

    nonce = num.to_bytes(32, 'little')
    sig = aes_sign(nonce, k_b3)
    msg = aes_encrypt(nonce + b'\n\n' + sig, k_a2)
    print('sending challenge response...')
    send(client_socket, msg)


if __name__ == '__main__':
    main()
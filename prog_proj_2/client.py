import socket
from myssl import *

all_msgs = []
PRIVATE_KEY = 'client.key'


''' returns client hello in bytes and saves to all_msgs array '''
def client_hello():
    print('sending client hello...')
    msg = bytes('client hello', 'ISO-8859-1')
    all_msgs.append(msg)
    return msg


''' returns 2nd client msg and nonce r_a back, 2nd client msg = cipher + encrypted nonce + client certificate '''
def get_client_cert_msg(server_cert):
    cipher = 'AES'.encode()
    cert = read_bytes('client.crt')
    r_a = get_nonce()
    enc_nonce = cert_encrypt(r_a.to_bytes(32,'little'), server_cert)
    
    print('r_a:',r_a)

    msg = cipher + '\n\n'.encode() + enc_nonce + '\n\n'.encode() + cert  
    return msg, r_a


''' decrypts recieved nonce from server '''
def recieve_r_b():
    msg = recieve(client)
    all_msgs.append(msg)
    r_b = cert_decrypt(bytes(msg), PRIVATE_KEY)
    r_b = int.from_bytes(r_b, 'little')
    print('r_b:',r_b)
    return r_b


''' hashes all the messages received plus CLIENT for HMAC '''
def generate_hmac(secret):
    hash = keyed_hash(all_msgs, secret, b'CLIENT')
    print('generated keyed hash:', hash)
    return hash


''' 
    after key exchange server and client engage in the following protocol:
    a --------------Kb2{r_a2, Ka3(r_a2))--------------> b
    a <-----------Ka2(r_a2 + 1, Kb3(r_a+1))------------ b
    they use their keys exchanged to encrypt, decrypt, sign and verify
    to ensure the keys are working
'''
def test_encryption(client, k_a2, k_a3, k_b2, k_b3):
    #send cahllenge
    r_a2 = get_nonce()
    nonce = r_a2.to_bytes(32, 'little')
    #sign challenge
    sig = aes_sign(nonce, k_a3)
    msg = aes_encrypt(nonce + b'\n\n' + sig, k_b2)
    print('sending ra2 challenge to server...')
    send(client, msg)

    response = aes_decrypt(bytes(recieve(client)), k_a2)
    print('received challenge response...')

    #verify signature first:
    response = response.split(b'\n\n', 1)
    num = response[0]
    sig = response[1]
    print('verifying signature...')
    aes_validate_sig(num, k_b3, sig)

    #validate recieved number
    if int.from_bytes(num, 'little') - 1 != r_a2:
        raise ValueError('Invalid response from server')
    print('success!')
    print('challenge complete! Encryption ready for use')
    

''' saves received file to the given path '''
def save_file(data, path):
    with open(path, "wb") as f:
        f.write(data)


''' MySSL handshake phase driver method '''
def handshake(client):
    send(client, client_hello())

    cert = recieve(client)
    all_msgs.append(cert)
    cert = get_cert(cert)

    print('recieved certificate from server...')
    validate(cert)

    msg, r_a = get_client_cert_msg(cert)
    print('sending certificate, cipher, encrypted nonce...')
    all_msgs.append(msg)
    send(client, msg)

    r_b = recieve_r_b()
    master_secret = r_a ^ r_b
    master_secret = base64.urlsafe_b64encode(master_secret.to_bytes(32, 'little'))
    print('master secret:', master_secret)
    hash = generate_hmac(master_secret)
    all_msgs.append(hash)
    send(client, hash)
    rec_hash = bytes(recieve(client))
    print('received hash:', rec_hash)
    compare_hashes(keyed_hash(all_msgs, master_secret, b'SERVER'), rec_hash)

    print('Authentication handshake complete!')
    return cert, master_secret

''' 
    exchange of derrived keys phase driver 

    a --------Kb+{k_a2, k_a3, K_a-{k_a2, k_a3}}--------> b
    a <-------Ka+{k_b2, k_b3, K_b-{k_a2, k_a3}}--------- b

    new derrived keys are then tested in test_encryption method
    new keys are derrived as a function of the master secret
'''
def key_exchange(client, server_cert, k_ab):
    k_a2, k_a3 = get_new_keys(k_ab)
    print('encryption key:', k_a2)
    print('signing key:', k_a3)

    plain_text = k_a2 + b'\n\n'+ k_a3
    sig = sign(plain_text, PRIVATE_KEY)
    msg = plain_text + b'\n\n' + sig

    msg = aes_encrypt(msg, k_ab)

    print('sending encrypted keys and signature to server...')
    send(client, msg)

    k_b2, k_b3, b_sig = get_keys_sig(recieve(client), k_ab)
    print('recieved server keys...')
    print('verifying server signature')
    verify_sig(server_cert, b_sig, k_b2 + b'\n\n'+ k_b3)
    print('signature valid!')

    test_encryption(client, k_a2, k_a3, k_b2, k_b3)

    return k_a2, k_a3, k_b2, k_b3


''' file download phase driver 

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
def download_file(client, decrpt_key, sign_key, srvr_enc_key, srvr_sign_key):
    file = 'tortoise_hare.txt'
    print('requesting', file)
    sig = aes_sign(file.encode(), sign_key)
    file_req = aes_encrypt(file.encode() + b'\n\n' + sig, srvr_enc_key)
    send(client, file_req)

    file_response = bytes(recieve(client))
    print('recieved encrypted file')
    print('decrypting bytes...')
    file_response = aes_decrypt(file_response, decrpt_key)

    recv = 'recieved'.encode()
    sig = aes_sign(recv, sign_key)
    send(client, aes_encrypt(recv + b'\n\n' + sig, srvr_enc_key))

    print('sending received notification')

    hashcode = aes_decrypt(bytes(recieve(client)), decrpt_key)
    hashcode = hashcode.split(b'\n\n', 1)
    sig = hashcode[1]
    hashcode = hashcode[0]

    print('verifying signature from server...')

    aes_validate_sig(hashcode, srvr_sign_key, sig)
    filehash = hashlib.md5(file_response).digest()
    print('comparing file hashes...')
    compare_hashes(hashcode, filehash)

    print('success! saving file')
    save_file(file_response, 'clientfiles/'+file)
    print('complete!')


'''
    driver method for entire connection
    connects to server and calls each phase individually
    handshake -> key exchange -> download file

    catches any exception that might be thrown throughout process
'''
def connect_and_download(client, HOST, PORT):
    #TODO
    try:
        client.connect((HOST,PORT))
        server_cert, k_ab = handshake(client)
        key, sign_key, srvr_key, srvr_sign_key = key_exchange(client, server_cert, k_ab)
        download_file(client, key, sign_key, srvr_key, srvr_sign_key) 
        
    except RuntimeError as re:
        print(re.args)
    except ValueError as ve:
        print(ve.args)
    except Exception as e:
        print(e.args)


''' main method: calls driver and closes client at the end '''
if __name__ == '__main__':
    HOST = '127.0.0.1'
    PORT = 9995
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect_and_download(client, HOST, PORT)
    client.close()
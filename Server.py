import socket
import threading
import json
import sys
import random
import utils

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec


def get_server_public_key_pem():
    """
    this function returns the server's public key in PEM format (bytes).
    :return: public key in a pem format
    """
    return utils.SERVER_PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def sign_data(data_bytes):
    """
    Sign data with the server's private key using ECDSA (SHA256).
    :param data_bytes: the data we want to sign in bytes
    :return: the signature in bytes.
    """
    signature = utils.SERVER_PRIVATE_KEY.sign(
        data_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def generate_otp_code():
    """
    Generate a random 6-digit OTP code.
    :return: a 6-digit string
    """
    return f"{random.randint(0, 999999):06d}"


def handle_client_connection(client_socket, address):
    """
    Handles request from the connected client.
    :param client_socket: the interface the server give us to connect
    :param address: the client's ip address
    """
    try:
        data = b""
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            data += chunk
            # Attempt to parse as JSON:
            try:
                request = json.loads(data.decode('utf-8'))
                break
            except json.JSONDecodeError:
                continue  # Not enough data yet

        if not data:
            client_socket.close()
            return

        response = process_request(request)
        response_json = json.dumps(response).encode('utf-8')
        client_socket.sendall(response_json)

    except Exception as e:
        print(f"Server~ Error handling client {address}: {e}")
    finally:
        client_socket.close()


def process_request(request):
    """
    based on the 'action' field in the JSON request, this function will handle a request.
    :return: dictionary that will contain the response as a json
    """
    action = request.get('action')

    if action == 'get_server_public_key':
        return handle_get_server_public_key(request)

    elif action == 'authenticate':  
        return handle_authenticate(request)

    elif action == 'verify_otp':  
        return SendBySecureChannel(request)

    elif action == 'register':
        return handle_register(request)

    elif action == 'get_user_public_key':
        return handle_get_user_public_key(request)
    
    elif action == 'login':
        return handle_login(request)

    elif action == 'logout':
        return handle_logout(request)

    elif action == 'store_message':
        return handle_store_message(request)

    elif action == 'fetch_messages':
        return handle_fetch_messages(request)

    else:
        return {"error": f"Unknown action: {action}"}


def handle_login(request):
    """
    adding the user to the online users list if they exist in USER_DB, if they dont exist there, return an error.
    :return: response
    """
    user_id = request.get("user_id")
    if not user_id:
        return {"error": "Missing user_id"}

    if user_id not in utils.USER_DB:
        return {"error": "User not found in DB. Please authenticate/register first."}

    # adding the user to the online users list
    utils.ONLINE_USERS.add(user_id)
    return {"status": "logged_in"}


def handle_logout(request):
    """
    removing a user from he online users list if they exist.
    """
    user_id = request.get("user_id")
    if not user_id:
        return {"error": "Missing user_id"}

    utils.ONLINE_USERS.discard(user_id)
    return {"status": "logged_out"}


def handle_get_server_public_key(request):
    """
    Return the servers public key PEM.
    :param request: the request from the client
    """
    pk_pem = get_server_public_key_pem().decode()
    return {"server_public_key_pem": pk_pem}


def handle_authenticate(request):
    """
    checks if user_id is already in USER_DB, if so,
    returns "already_registered" else, will generate an OTP, store in OTP_CODES,
    and return the OTP to the client.
    :param request: the request from the client
    """
    user_id = request.get("user_id")
    if not user_id:
        return {"error": "Missing user_id"}

    if user_id in utils.USER_DB:
        # Already registered, skipping OTP
        return {"status": "already_registered"}

    # Not in DB, generating OTP and storing it
    code = generate_otp_code()
    utils.OTP_CODES[user_id] = code

    return {
        "status": "otp_sent",
        "otp_code_demo": code
    }


def SendBySecureChannel(request):
    """
    the function checks if the request matches the stored code in OTP_CODES.
    If so, it will add user_id to VERIFIED_USERS.
    :param request: the request from the client
    """
    user_id = request.get("user_id")
    otp_code = request.get("otp_code")

    if not user_id or not otp_code:
        return {"error": "Missing user_id or otp_code"}

    # Check if we have a code stored
    stored_code = utils.OTP_CODES.get(user_id)
    if not stored_code:
        return {"error": "No OTP found for this user_id..."}

    if otp_code == stored_code:
        # OTP is correct
        utils.VERIFIED_USERS.add(user_id)
        # Remove from OTP_CODES so it can't be reused
        del utils.OTP_CODES[user_id]
        return {"status": "otp_verified"}
    else:
        return {"error": "Invalid OTP code"}


def handle_register(request):
    """
    if user_id is already in USER_DB, we will skip registration, else, 
    we will check if user_id is in VERIFIED_USERS (passed OTP),
    if not, reject.
    then we will store (user_id -> public_key_pem) in USER_DB
    and create an empty message queue for them.
    finally, we sign (user_id + public_key_pem) and return the signature.
    :param request: the request from the client
    """
    user_id = request.get("user_id")
    public_key_pem_str = request.get("public_key_pem")

    if not user_id or not public_key_pem_str:
        return {"error": "Invalid register request: missing user_id or public_key_pem"}

    # If user is *already* in DB, skip re-register
    if user_id in utils.USER_DB:
        return {"status": "already_registered"}

    # Check if user_id passed OTP
    if user_id not in utils.VERIFIED_USERS:
        return {"error": "User has not passed OTP verification. Call verify_otp first."}

    # Passed OTP => proceed to register
    public_key_pem = public_key_pem_str.encode('utf-8')
    utils.USER_DB[user_id] = {"public_key_pem": public_key_pem}
    utils.MESSAGE_QUEUE[user_id] = []

    # Remove from VERIFIED_USERS now that they are in DB
    utils.VERIFIED_USERS.remove(user_id)

    # Sign user_id + public_key
    to_sign = user_id.encode('utf-8') + public_key_pem
    signature = sign_data(to_sign)
    signature_hex = signature.hex()

    return {
        "status": "ok",
        "signature": signature_hex
    }


def handle_get_user_public_key(request):
    """
    returns the public key of the user
    :param request: the request from the client
    """
    target_user_id = request.get("target_user_id")
    if not target_user_id or target_user_id not in utils.USER_DB:
        return {"error": f"User {target_user_id} not found in database"}

    pub_key_pem = utils.USER_DB[target_user_id]["public_key_pem"]
    return {"public_key_pem": pub_key_pem.decode('utf-8')}


def handle_store_message(request):
    """
    here we will store the given message
    :param request: the request from the client
    """
    recipient_id = request.get("recipient_id")
    envelope = request.get("envelope")

    if recipient_id not in utils.MESSAGE_QUEUE:
        return {"error": f"Recipient {recipient_id} not found in DB. Not registered?"}

    utils.MESSAGE_QUEUE[recipient_id].append(envelope)
    return {"status": "stored"}


def handle_fetch_messages(request):
    """
    get all messages from the message_queue by the user_id
    :param request: the request from the client
    """
    user_id = request.get("user_id")
    if user_id not in utils.MESSAGE_QUEUE:
        return {"messages": []}

    queued = utils.MESSAGE_QUEUE[user_id]
    utils.MESSAGE_QUEUE[user_id] = []
    return {"messages": queued}


def main():
    # Default host and port, so we can run client and server from the same computer
    host = "0.0.0.0"
    port = 5000

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server~ Listening on {host}:{port}")

    try:
        while True:
            client_sock, addr = server_socket.accept()
            print(f"Server~ Incoming connection from {addr}")
            # making a client a thread
            t = threading.Thread(target=handle_client_connection, args=(client_sock, addr))
            t.start()

    except KeyboardInterrupt:
        print("Server~ Shutting down.")
        server_socket.close()
        sys.exit(0)

if __name__ == "__main__":
    main()

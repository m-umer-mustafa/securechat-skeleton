"""
SecureChat Server Application - Accepts encrypted client connections
over plain TCP, implementing PKI validation and application-layer crypto.
"""
import socket
import json
import struct
import time
from hashlib import sha256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography import x509

from app.crypto.pki import (
    load_certificate_pem,
    verify_peer_certificate,
    BadCertificate,
)
from app.crypto.dh import (
    generate_dh_keypair,
    load_peer_public_key,
    derive_shared_key,
)
from app.common.utils import recv_cert, send_cert, recv_dh_pub, send_dh_pub
from app.crypto.aes import aes_encrypt_ecb, aes_decrypt_ecb
from app.storage.db import create_user, verify_user
from app.crypto.chat import (
    load_private_key,
    build_chat_message,
    parse_chat_message,
)

SERVER_IDENTITY = "server.local"
LISTEN_PORT = 9000


def main():
    # Load Root CA certificate for client validation
    root_ca_certificate = load_certificate_pem("certs/ca/ca_cert.pem")
    # Load server's own certificate and private key
    my_certificate = load_certificate_pem("certs/server/cert.pem")
    my_private_key = load_private_key("certs/server/key.pem")  

    # Read server certificate in PEM format for transmission
    with open("certs/server/cert.pem", "rb") as cert_file:
        my_cert_bytes = cert_file.read()

    # Create plain TCP server socket (no TLS)
    with socket.create_server(("0.0.0.0", LISTEN_PORT)) as listener_socket:
        print(f"Server is listening on port {LISTEN_PORT}...")

        while True:
            client_socket, client_address = listener_socket.accept()
            with client_socket:
                # Step 1: Receive and validate client certificate
                try:
                    client_cert_bytes = recv_cert(client_socket)
                    print(f"[CONNECTION] Accepted from {client_address}")
                except Exception as handshake_error:
                    print(f"[HANDSHAKE_FAILURE] Error from {client_address}: {handshake_error}")
                    continue

                # Parse client certificate from PEM format
                client_x509_cert = x509.load_pem_x509_certificate(client_cert_bytes)
                client_public_key = client_x509_cert.public_key()

                # Validate client certificate against Root CA
                try:
                    verify_peer_certificate(
                        client_x509_cert,
                        root_ca_certificate,
                        expected_hostname="client.local",
                    )
                    print(f"[CERT_VALID] Client certificate verified from {client_address}")
                except BadCertificate as cert_error:
                    # Certificate validation failed, reject connection
                    print(f"[CERT_INVALID] Rejected certificate from {client_address}: {cert_error}")
                    continue

                # Step 2: Transmit server certificate to client
                print(f"[TX_CERT] Sending certificate to {client_address}")
                send_cert(client_socket, my_cert_bytes)

                # Step 3: DH key exchange - server generates keypair and initiates
                print(f"[DH_KEYGEN] Generating server DH keypair for {client_address}")
                my_dh_keypair = generate_dh_keypair()
                print(f"[DH_TX] Transmitting server DH public key to {client_address}")
                send_dh_pub(client_socket, my_dh_keypair.public_bytes)

                # Step 4: Receive client's DH public key
                try:
                    print(f"[DH_EXCHANGE] Awaiting client DH public key from {client_address}")
                    client_dh_public_bytes = recv_dh_pub(client_socket)
                except Exception as dh_error:
                    print(f"[DH_FAILURE] Error from {client_address}: {dh_error}")
                    continue

                # Step 5: Derive shared AES key via DH
                client_dh_public = load_peer_public_key(client_dh_public_bytes)
                handshake_aes_key = derive_shared_key(my_dh_keypair.private_key, client_dh_public)
                print(f"[DH_COMPLETE] Derived shared AES key for {client_address}: {handshake_aes_key.hex()}")

                # === Process User Registration ===
                # Receive length-prefixed encrypted registration data
                length_header = client_socket.recv(4)
                if not length_header:
                    print(f"[REGISTER] No registration data from {client_address}")
                    continue
                (ciphertext_length,) = struct.unpack("!I", length_header)
                encrypted_payload = client_socket.recv(ciphertext_length)
                if len(encrypted_payload) != ciphertext_length:
                    print(f"[REGISTER] Incomplete registration payload from {client_address}")
                    continue

                # Decrypt and parse registration JSON
                try:
                    decrypted_json = aes_decrypt_ecb(handshake_aes_key, encrypted_payload)
                    registration_data = json.loads(decrypted_json.decode("utf-8"))
                except Exception as decrypt_error:
                    print(f"[REGISTER_ERROR] Invalid registration payload from {client_address}: {decrypt_error}")
                    continue

                if registration_data.get("type") != "register":
                    print(f"[REGISTER_ERROR] Unexpected message type from {client_address}: {registration_data!r}")
                    continue

                user_email = registration_data.get("email")
                user_name = registration_data.get("username")
                user_password = registration_data.get("password")

                if not (user_email and user_name and user_password):
                    print(f"[REGISTER_ERROR] Missing required fields from {client_address}: {registration_data!r}")
                    continue

                try:
                    create_user(user_email, user_name, user_password)
                    print(f"[REGISTER_SUCCESS] User '{user_name}' registered from {client_address}")
                except Exception as db_error:
                    print(f"[REGISTER_DB_ERROR] Failed to create user '{user_name}': {db_error}")
                    continue

                # === Process User Authentication ===
                # Receive length-prefixed encrypted login data
                length_header = client_socket.recv(4)
                if not length_header:
                    print(f"[AUTHENTICATE] No login data from {client_address}")
                    continue
                (ciphertext_length,) = struct.unpack("!I", length_header)
                encrypted_payload = client_socket.recv(ciphertext_length)
                if len(encrypted_payload) != ciphertext_length:
                    print(f"[AUTHENTICATE] Incomplete login payload from {client_address}")
                    continue

                # Decrypt and parse login JSON
                try:
                    decrypted_json = aes_decrypt_ecb(handshake_aes_key, encrypted_payload)
                    authentication_data = json.loads(decrypted_json.decode("utf-8"))
                except Exception as decrypt_error:
                    print(f"[AUTHENTICATE_ERROR] Invalid login payload from {client_address}: {decrypt_error}")
                    continue

                if authentication_data.get("type") != "login":
                    print(f"[AUTHENTICATE_ERROR] Unexpected message type from {client_address}: {authentication_data!r}")
                    continue

                login_username = authentication_data.get("username")
                login_password = authentication_data.get("password")

                if not (login_username and login_password):
                    print(f"[AUTHENTICATE_ERROR] Missing fields from {client_address}: {authentication_data!r}")
                    continue

                # Verify credentials against database
                try:
                    authentication_successful = verify_user(login_username, login_password)
                    if authentication_successful:
                        print(f"[AUTHENTICATE_SUCCESS] User '{login_username}' authenticated from {client_address}")
                        response_payload = json.dumps({"status": "ok"}).encode("utf-8")
                    else:
                        print(f"[AUTHENTICATE_FAILURE] Invalid credentials for '{login_username}' from {client_address}")
                        response_payload = json.dumps({"status": "error", "reason": "invalid_credentials"}).encode("utf-8")

                    encrypted_response = aes_encrypt_ecb(handshake_aes_key, response_payload)
                    client_socket.sendall(struct.pack("!I", len(encrypted_response)) + encrypted_response)
                except Exception as db_error:
                    print(f"[AUTHENTICATE_DB_ERROR] Error for user '{login_username}': {db_error}")
                    response_payload = json.dumps({"status": "error", "reason": "server_error"}).encode("utf-8")
                    encrypted_response = aes_encrypt_ecb(handshake_aes_key, response_payload)
                    client_socket.sendall(struct.pack("!I", len(encrypted_response)) + encrypted_response)
                    continue

                # === Establish Session Key (Post-Authentication DH) ===
                if authentication_successful:
                    print(f"[SESSION_SETUP] Generating server session DH keypair for {client_address}")
                    my_session_dh = generate_dh_keypair()
                    print(f"[SESSION_TX] Sending server session DH public key to {client_address}")
                    send_dh_pub(client_socket, my_session_dh.public_bytes)

                    try:
                        print(f"[SESSION_EXCHANGE] Awaiting client session DH public key from {client_address}")
                        client_session_dh_bytes = recv_dh_pub(client_socket)
                    except Exception as session_error:
                        print(f"[SESSION_FAILURE] Error from {client_address}: {session_error}")
                        continue

                    client_session_public = load_peer_public_key(client_session_dh_bytes)
                    chat_session_key = derive_shared_key(my_session_dh.private_key, client_session_public)
                    print(f"[SESSION_ESTABLISHED] Derived session AES key for {client_address}: {chat_session_key.hex()}")

                    # Transmit encrypted session confirmation message
                    confirmation_message = json.dumps({"type": "session", "status": "ready"}).encode("utf-8")
                    encrypted_confirmation = aes_encrypt_ecb(chat_session_key, confirmation_message)
                    client_socket.sendall(struct.pack("!I", len(encrypted_confirmation)) + encrypted_confirmation)

                    # === Encrypted Chat Loop (Secure Data Plane) ===
                    print(f"[CHAT_READY] Starting secure chat session with {client_address}")
                    server_message_number = 0
                    last_received_sequence = 0
                    session_transcript = []  # Append-only transcript for non-repudiation
                    
                    while True:
                        # Receive one encrypted chat message from client
                        header_bytes = client_socket.recv(4)
                        if not header_bytes:
                            print(f"[CHAT] Client {client_address} disconnected")
                            break
                        (incoming_msg_length,) = struct.unpack("!I", header_bytes)
                        message_body = client_socket.recv(incoming_msg_length)
                        if len(message_body) != incoming_msg_length:
                            print(f"[CHAT] Incomplete message from {client_address}")
                            break

                        try:
                            decrypted_message, last_received_sequence = parse_chat_message(
                                header_bytes + message_body, chat_session_key, client_public_key, last_received_sequence
                            )
                            print(f"[CHAT_RX] From {client_address}: {decrypted_message!r}")

                            # Record inbound message metadata
                            timestamp = time.time()
                            transcript_line = f"RX|{last_received_sequence}|{timestamp}|client|{decrypted_message}\n"
                            session_transcript.append(transcript_line)
                        except Exception as message_error:
                            print(f"[SIG_INVALID] Invalid message from {client_address}: {message_error}")
                            break

                        # Generate server reply (echo response)
                        reply_message = f"Echo: {decrypted_message}"
                        server_message_number += 1
                        wire_reply = build_chat_message(
                            server_message_number, chat_session_key, my_private_key, reply_message
                        )
                        client_socket.sendall(wire_reply)

                        # Record outbound message metadata
                        timestamp = time.time()
                        transcript_line = f"TX|{server_message_number}|{timestamp}|client|{reply_message}\n"
                        session_transcript.append(transcript_line)
                    # Chat loop complete

                    # === Generate Session Receipt (Non-Repudiation) ===
                    transcript_complete = "".join(session_transcript).encode("utf-8")
                    transcript_digest = sha256(transcript_complete).digest()

                    # Sign transcript hash with server's RSA private key
                    server_signature = my_private_key.sign(
                        transcript_digest,
                        asym_padding.PKCS1v15(),
                        hashes.SHA256(),
                    )

                    print("[RECEIPT] Server transcript SHA256:", transcript_digest.hex())
                    print("[RECEIPT] Server digital signature:", server_signature.hex())

                    # Write receipt to file for offline verification
                    with open("server_session_receipt.txt", "w", encoding="utf-8") as receipt_file:
                        receipt_file.write("TRANSCRIPT:\n")
                        receipt_file.writelines(session_transcript)
                        receipt_file.write("\nHASH:" + transcript_digest.hex() + "\n")
                        receipt_file.write("SIG:" + server_signature.hex() + "\n")


if __name__ == "__main__":
    main()
    print("Server application terminated.")
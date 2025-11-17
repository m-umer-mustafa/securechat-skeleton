"""
SecureChat Client Application - Establishes encrypted communication
over plain TCP without TLS, implementing application-layer cryptography.
"""

import socket
import struct
import json
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
from app.crypto.chat import (
    load_private_key,
    build_chat_message,
    parse_chat_message,
)

TARGET_SERVER = "127.0.0.1"
SERVER_PORT = 9000


def main():
    # Load CA certificate for server validation
    root_ca_certificate = load_certificate_pem("certs/ca/ca_cert.pem")
    # Load client's own certificate and private key
    my_certificate = load_certificate_pem("certs/client/cert.pem")
    my_private_key = load_private_key("certs/client/key.pem")  

    # Read client certificate in PEM format for transmission
    with open("certs/client/cert.pem", "rb") as cert_file:
        my_cert_bytes = cert_file.read()

    # Establish plain TCP connection (no TLS layer)
    with socket.create_connection((TARGET_SERVER, SERVER_PORT)) as tcp_socket:
        remote_address = tcp_socket.getpeername()
        print(f"Established connection to server: {remote_address}")

        # Step 1: Transmit client certificate to server for authentication
        print(f"[TX_CERT] Sending certificate to {remote_address}")
        send_cert(tcp_socket, my_cert_bytes)

        # Step 2: Receive and validate server's certificate
        try:
            server_cert_bytes = recv_cert(tcp_socket)
            print(f"[RX_CERT] Received server certificate from {remote_address}")
        except Exception as error:
            print(f"[HANDSHAKE_FAILURE] Error from {remote_address}: {error}")
            return

        # Parse server certificate from PEM bytes
        server_x509_cert = x509.load_pem_x509_certificate(server_cert_bytes)
        server_public_key = server_x509_cert.public_key()

        # Validate server certificate against CA
        try:
            verify_peer_certificate(
                server_x509_cert,
                root_ca_certificate,
                expected_hostname="server.local",
            )
            print(f"[CERT_VALID] Server certificate verified from {remote_address}")
        except BadCertificate as cert_error:
            # Certificate validation failed, abort connection
            print(f"[CERT_INVALID] Certificate error from {remote_address}: {cert_error}")
            return

        # Step 3: Receive server's DH public key (initiates key exchange)
        try:
            print(f"[DH_EXCHANGE] Awaiting server's DH public key from {remote_address}")
            server_dh_public_bytes = recv_dh_pub(tcp_socket)
        except Exception as dh_error:
            print(f"[DH_FAILURE] Error receiving DH key from {remote_address}: {dh_error}")
            return

        # Load server's DH public key for shared secret computation
        server_dh_public = load_peer_public_key(server_dh_public_bytes)

        # Step 4: Generate client DH keypair and transmit public portion
        print(f"[DH_KEYGEN] Creating DH keypair for session with {remote_address}")
        my_dh_keypair = generate_dh_keypair()
        print(f"[DH_TX] Transmitting client DH public key to {remote_address}")
        send_dh_pub(tcp_socket, my_dh_keypair.public_bytes)

        # Step 5: Compute shared AES encryption key via DH
        handshake_aes_key = derive_shared_key(my_dh_keypair.private_key, server_dh_public)
        print(f"[DH_COMPLETE] Derived shared AES key for {remote_address}: {handshake_aes_key.hex()}")

        # === User Registration Phase ===
        # Prepare registration credentials (hardcoded for demonstration)
        user_email = "alice14@example.com"
        user_name = "alice14"
        user_password = "supersecret"

        registration_data = {
            "type": "register",
            "email": user_email,
            "username": user_name,
            "password": user_password,
        }
        registration_json = json.dumps(registration_data).encode("utf-8")

        # Encrypt registration payload using AES-ECB with shared key
        encrypted_registration = aes_encrypt_ecb(handshake_aes_key, registration_json)

        # Transmit: 4-byte length prefix followed by encrypted payload
        tcp_socket.sendall(struct.pack("!I", len(encrypted_registration)) + encrypted_registration)
        print(f"[REGISTER] Registration data transmitted to {remote_address}")

        # === User Authentication Phase ===
        authentication_payload = {
            "type": "login",
            "username": user_name,
            "password": user_password,
        }
        authentication_json = json.dumps(authentication_payload).encode("utf-8")
        encrypted_login = aes_encrypt_ecb(handshake_aes_key, authentication_json)

        tcp_socket.sendall(struct.pack("!I", len(encrypted_login)) + encrypted_login)
        print(f"[AUTHENTICATE] Login credentials transmitted to {remote_address}")

        # Wait for encrypted authentication response
        response_length_data = tcp_socket.recv(4)
        if not response_length_data:
            print("[AUTHENTICATE] No response received from server")
            return
        (response_length,) = struct.unpack("!I", response_length_data)
        encrypted_response = tcp_socket.recv(response_length)
        decrypted_response = aes_decrypt_ecb(handshake_aes_key, encrypted_response)
        print("[AUTHENTICATE] Server response:", decrypted_response.decode("utf-8"))

        # Parse authentication response JSON
        try:
            auth_response = json.loads(decrypted_response.decode("utf-8"))
        except Exception:
            print("[AUTHENTICATE] Invalid JSON in server response")
            return

        if auth_response.get("status") != "ok":
            print("[AUTHENTICATE] Login failed, session will not be established")
            return

        # === Session Key Establishment (Post-Authentication DH) ===
        try:
            print(f"[SESSION_SETUP] Awaiting server's session DH public key from {remote_address}")
            server_session_dh_bytes = recv_dh_pub(tcp_socket)
        except Exception as session_error:
            print(f"[SESSION_FAILURE] Error from {remote_address}: {session_error}")
            return

        server_session_public = load_peer_public_key(server_session_dh_bytes)

        print(f"[SESSION_KEYGEN] Generating client session DH keypair for {remote_address}")
        my_session_dh = generate_dh_keypair()
        print(f"[SESSION_TX] Sending client session DH public key to {remote_address}")
        send_dh_pub(tcp_socket, my_session_dh.public_bytes)

        # Derive session-specific AES key for chat messages
        chat_session_key = derive_shared_key(my_session_dh.private_key, server_session_public)
        print(f"[SESSION_ESTABLISHED] Derived session AES key for {remote_address}: {chat_session_key.hex()}")

        # Receive encrypted session confirmation message
        session_msg_len_data = tcp_socket.recv(4)
        if not session_msg_len_data:
            print("[SESSION] No session-ready confirmation from server")
            return
        (session_msg_len,) = struct.unpack("!I", session_msg_len_data)
        encrypted_session_msg = tcp_socket.recv(session_msg_len)
        decrypted_session_msg = aes_decrypt_ecb(chat_session_key, encrypted_session_msg)
        print("[SESSION] Server confirmation:", decrypted_session_msg.decode("utf-8"))

        # === Secure Chat Loop (Encrypted Data Exchange) ===
        print("[CHAT_READY] Enter your messages (press Enter on empty line to exit)")
        client_message_number = 0
        last_received_sequence = 0
        session_transcript = []  # Stores metadata for non-repudiation
        previous_wire_message = None  # For testing replay attacks
        previous_message_text = None

        while True:
            try:
                message_text = input("> ")
            except EOFError:
                break
            if not message_text:
                break

            client_message_number += 1
            wire_message = build_chat_message(client_message_number, chat_session_key, my_private_key, message_text)
            previous_wire_message = wire_message
            previous_message_text = message_text

            tcp_socket.sendall(wire_message)

            # Record outbound message metadata
            timestamp = time.time()
            transcript_line = f"TX|{client_message_number}|{timestamp}|server|{message_text}\n"
            session_transcript.append(transcript_line)

            # Receive server's encrypted reply
            header_bytes = tcp_socket.recv(4)
            if not header_bytes:
                print("[CHAT] Server disconnected")
                break
            (incoming_msg_length,) = struct.unpack("!I", header_bytes)
            message_body = tcp_socket.recv(incoming_msg_length)
            if len(message_body) != incoming_msg_length:
                print("[CHAT] Incomplete message from server")
                break

            try:
                decrypted_reply, last_received_sequence = parse_chat_message(
                    header_bytes + message_body, chat_session_key, server_public_key, last_received_sequence
                )
                print(f"[CHAT_RX] Server says: {decrypted_reply}")

                # Record inbound message metadata
                timestamp = time.time()
                transcript_line = f"RX|{last_received_sequence}|{timestamp}|server|{decrypted_reply}\n"
                session_transcript.append(transcript_line)
            except Exception as message_error:
                print(f"[CHAT_ERROR] Invalid message from server: {message_error}")
                break
        # Chat loop complete

        # === Generate Session Receipt (Non-Repudiation) ===
        transcript_complete = "".join(session_transcript).encode("utf-8")
        transcript_digest = sha256(transcript_complete).digest()

        # Sign transcript hash with client's RSA private key
        client_signature = my_private_key.sign(
            transcript_digest,
            asym_padding.PKCS1v15(),
            hashes.SHA256(),
        )

        print("[RECEIPT] Client transcript SHA256:", transcript_digest.hex())
        print("[RECEIPT] Client digital signature:", client_signature.hex())

        # Write receipt to file for offline verification
        with open("client_session_receipt.txt", "w", encoding="utf-8") as receipt_file:
            receipt_file.write("TRANSCRIPT:\n")
            receipt_file.writelines(session_transcript)
            receipt_file.write("\nHASH:" + transcript_digest.hex() + "\n")
            receipt_file.write("SIG:" + client_signature.hex() + "\n")


if __name__ == "__main__":
    main()
    print("Client application terminated.")

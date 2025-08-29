
import struct
import os
from server_model import Client, ServerModel, Message
from server_view import ServerView
from protocol_constants import UUID_SIZE, PUBLIC_KEY_SIZE, CLIENT_NAME_SIZE, PACKED_CLIENT_ENTRY_SIZE, REGISTER_REPLY_SIZE, RESPONSE_HEADER_SIZE, Code

HEADER_FORMAT = f'!{UUID_SIZE}sBHI'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
REGISTER_PAYLOAD_FORMAT = f'!{CLIENT_NAME_SIZE}s{PUBLIC_KEY_SIZE}s'
REGISTER_PAYLOAD_SIZE = struct.calcsize(REGISTER_PAYLOAD_FORMAT)

ERROR_RESPONSE_BYTES = struct.pack('!BHI', 1, Code.ERROR, 0)


class ServerController:
    def __init__(self, model: ServerModel, view: ServerView):
        self.model = model
        self.view = view

    def handle_client(self, conn):
        self.view.log("Handling new client connection")
        while True:
            try:
                header_bytes = conn.recv(HEADER_SIZE)
                if not header_bytes or len(header_bytes) < HEADER_SIZE:
                    self.view.log(
                        "Received incomplete header, closing connection")
                    return

                client_id, version, code, payload_size = struct.unpack(
                    HEADER_FORMAT, header_bytes)
                self.view.log(
                    f"Header: client_id={client_id.hex()}, version={version}, code={code}, payload_size={payload_size}")

                payload = b''
                while len(payload) < payload_size:
                    chunk = conn.recv(payload_size - len(payload))
                    if not chunk:
                        raise Exception("Incomplete payload")
                    payload += chunk

                if code == Code.REGISTER:
                    if len(payload) != REGISTER_PAYLOAD_SIZE:
                        self.view.log("Invalid register payload size")
                        raise Exception("Invalid register payload size")
                    username_bytes, public_key_bytes = struct.unpack(
                        REGISTER_PAYLOAD_FORMAT, payload)
                    username = username_bytes.split(
                        b'\x00', 1)[0].decode(errors='ignore')
                    self.view.log(
                        f"Register request: username={username}, public_key={public_key_bytes.hex()[:16]}...")

                    client_uuid = os.urandom(UUID_SIZE)
                    client = Client(client_uuid, username, public_key_bytes)
                    self.model.register_client(client)

                    # Build response: 1 byte version, 2 bytes code (2100), 4 bytes payload_size (UUID_SIZE), UUID_SIZE bytes UUID
                    resp_header = struct.pack(
                        '!BHI', 1, Code.REGISTER_REPLY, UUID_SIZE)
                    resp = resp_header + client_uuid
                    self.view.log("Sending response: " + resp.hex())
                    conn.sendall(resp)
                elif code == Code.CLIENT_LIST:
                    # Build payload: all clients except the requester
                    debug_clients = self.model.all_clients()
                    self.view.log(f"Requesting client_id: {client_id.hex()}")
                    for c in debug_clients:
                        self.view.log(
                            f"Candidate client_id: {c.client_id.hex()} ==? {client_id.hex()} -> {c.client_id.hex() == client_id.hex()}")
                    clients = [
                        c for c in debug_clients if c.client_id.hex() != client_id.hex()]
                    payload = b''
                    for c in clients:
                        payload += c.client_id
                        name_bytes = c.username.encode(errors='ignore')[
                            :CLIENT_NAME_SIZE]
                        name_bytes = name_bytes.ljust(
                            CLIENT_NAME_SIZE, b'\x00')
                        payload += name_bytes
                    payload_size = len(payload)
                    resp_header = struct.pack(
                        '!BHI', 1, Code.CLIENT_LIST_REPLY, payload_size)
                    resp = resp_header + payload
                    self.view.log(
                        f"Sending client list response: {len(clients)} clients, payload_size={payload_size}")
                    conn.sendall(resp)
                elif code == Code.PUBLIC_KEY_REQUEST:
                    # Payload: UUID_SIZE bytes client id
                    if payload_size != UUID_SIZE:
                        self.view.log(
                            "Invalid public key request payload size")
                        conn.sendall(ERROR_RESPONSE_BYTES)
                        return
                    requested_id = payload
                    client = self.model.get_client(requested_id)
                    if client is None:
                        self.view.log("Requested client not found")
                        conn.sendall(ERROR_RESPONSE_BYTES)
                        return
                    # Build response: 1 byte version, 2 bytes code (2102), 4 bytes payload_size (UUID_SIZE+PUBLIC_KEY_SIZE), UUID_SIZE bytes id, PUBLIC_KEY_SIZE bytes pubkey
                    resp_payload = client.client_id + client.public_key
                    resp_header = struct.pack(
                        '!BHI', 1, Code.PUBLIC_KEY_REPLY, len(resp_payload))
                    resp = resp_header + resp_payload
                    self.view.log(
                        f"Sending public key response for client {client.client_id.hex()}")
                    conn.sendall(resp)
                elif code == Code.SEND_MESSAGE_REQUEST:
                    # Payload struct: dst_id (16s), msg_type (B), content_size (I), content (content_size)s
                    MSG_HEADER_FORMAT = f'!{UUID_SIZE}sBI'
                    MSG_HEADER_SIZE = struct.calcsize(MSG_HEADER_FORMAT)
                    if payload_size < MSG_HEADER_SIZE:
                        self.view.log("Invalid send message payload size")
                        conn.sendall(ERROR_RESPONSE_BYTES)
                        return
                    dst_id, msg_type, content_size = struct.unpack(
                        MSG_HEADER_FORMAT, payload[:MSG_HEADER_SIZE])
                    content = payload[MSG_HEADER_SIZE:MSG_HEADER_SIZE+content_size]
                    # Save message in model
                    msg = Message(
                        msg_id=0,  # will be set by add_message
                        to_client=dst_id,
                        from_client=client_id,
                        msg_type=msg_type,
                        content=content
                    )
                    self.model.add_message(msg)
                    # Build response struct: version (B), code (H), payload_size (I), dst_id (16s), msg_id (I)
                    REPLY_FORMAT = f'!BHI{UUID_SIZE}sI'
                    reply_payload = struct.pack(
                        f'!{UUID_SIZE}sI', dst_id, msg.msg_id)
                    reply_header = struct.pack(
                        '!BHI', 1, Code.SEND_MESSAGE_REPLY, struct.calcsize(f'!{UUID_SIZE}sI'))
                    resp = reply_header + reply_payload
                    self.view.log(
                        f"Send message: saved msg_id={msg.msg_id} for dst={dst_id.hex()}")
                    conn.sendall(resp)
                else:
                    # Unknown command, send error code with empty payload
                    self.view.log("Sending error response: " +
                                  ERROR_RESPONSE_BYTES.hex())
                    conn.sendall(ERROR_RESPONSE_BYTES)
            except Exception as e:
                self.view.log(f"Exception: {e}")
                conn.close()
                return

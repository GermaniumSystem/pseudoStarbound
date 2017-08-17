#!/usr/bin/python3

"""
A simple Starbound-compatible server designed to function as a quick-n'-dirty fallback.
"""

import asyncio
import configparser
import datetime
import os
import random
import struct

config_file = "config/config.cfg"
example_cfg = "config/example.cfg"

packet_ids = {}
packet_ids['proto_request'] =   { 743: b'\x00',  # 1.3.2
                                  742: b'\x00',  # 1.3
                                  729: b'\x00',  # 1.2
                                  724: b'\x00',  # 1.1
                                  723: b'\x09' } # 1.0 - Questionable implementation. I don't have a copy to test with.
# Can't support versions before 1.0. Their archetecture is different enough to make it impossible.

packet_ids['proto_response'] =  { 743: b'\x01',
                                  742: b'\x01',
                                  729: b'\x01',
                                  724: b'\x01',
                                  723: b'\x01' }

packet_ids['client_connect'] =  { 743: b'\x0c',
                                  742: b'\x0c',
                                  729: b'\x0b',
                                  724: b'\x0a',
                                  723: b'\x0a' }

packet_ids['connect_failure'] = { 743: b'\x04',
                                  742: b'\x04',
                                  729: b'\x04',
                                  724: b'\x04',
                                  723: b'\x03' }

payloads  =  {"good_proto": b'\x02\x01',
              "bad_proto":  b'\x02\x00'} # VLQ (\x02) + True/false.

def log(msg):
    """Given a msg, print it to stdout and write it to log_file."""
    print("{}: {}".format(datetime.datetime.utcnow().isoformat(), msg))
    lf = open(log_file, 'a')
    lf.write("{}: {}\n".format(datetime.datetime.utcnow().isoformat(), msg))
    lf.close()


# Shamefully taken from https://github.com/StarryPy/StarryPy3k/ because VLQs suck. :c
def build_signed_VLQ(length):
    """Given a length, return a signed VLQ representation of the value."""
    result = bytearray()
    value = abs(int(length) * 2)
    if length == 0:
        result = bytearray(b'\x00')
    else:
        while value > 0:
            byte = value & 0x7f
            value >>= 7
            if value != 0:
                byte |= 0x80
            result.insert(0, byte)
        if len(result) > 1:
            result[0] |= 0x80
            result[-1] ^= 0x80
    return bytes(result)


# Again, shamefully taken from StarryPy3k, because VLQs suck.
def read_signed_VLQ(reader):
    """Given a reader, read data as a signed VLQ and return its value."""
    d = b""
    v = 0
    while True:
        tmp = yield from reader.readexactly(1)
        d += tmp
        tmp = ord(tmp)
        v <<= 7
        v |= tmp & 0x7f
        if tmp & 0x80 == 0:
            break
    if (v & 1) == 0x00:
        return v >> 1
    else:
        return -((v >> 1) + 1)


def read_packet(reader):
    """
    Given a reader, read a packet_id, decode the VLQ, and read contents.

    :param reader: Stream to receive packets from.
    :return: Tuple: The packet_id and data from the packet.
    """
    packet_id = (yield from reader.readexactly(1))
    packet_len = (yield from read_signed_VLQ(reader))
    data = (yield from reader.readexactly(abs(packet_len)))
    return packet_id, data


async def handle_tcp_connection(reader, writer):
    """
    Given a reader and writer, wait for new connections and respond with a protocol-compliant
    disconnect upon successful connection.
    Handle connections in two steps:
    1. Respond to a protocol_request:
        - If the protocol version is expected, send a protocol_response containing the
          "good_proto" payload.
        - If the protocol version is unexpected, send a protocol_response containing the
          "bad_proto" payload.
    2. Respond to a client_connect:
        - Load a status_message from the status_file and send a connect_failure containing the
          encoded status_message.
    If an unexpected packet_id is received at any point, disconnect.

    :param reader: Stream to receive packets from.
    :param writer: Stream to send packets to.
    :return: Null.
    """

    host = writer.get_extra_info('peername')[0]
    log("Connection received from {}.".format(host))
    try:
        packet_id, data = await asyncio.wait_for(read_packet(reader), timeout=timeout)
    except:
        log(" - Lost connection to {}.".format(host))
        writer.close()
        return
    if packet_id in packet_ids["proto_request"].values():
        try:
            proto = int.from_bytes(data[2:], byteorder='big')
        except:
            log("- Failed to parse protocol_request protocol ({}). Aborting connection to {}..."
                "".format(data[2:],host))
            writer.close()
            return
        if proto in packet_ids['proto_request'].keys():
            log("- Received known protocol {} from {}. Continuing...".format(proto,host))
            writer.write(packet_ids["proto_response"][proto] + payloads["good_proto"])
            await writer.drain()
        else:
            log("- Unsupported protocol ({}). Aborting connection to {}...".format(proto,host))
            # If we're unfamiliar with the protocol, fallback to using the highest (and hopefully newest) protocol's ID.
            writer.write(packet_ids["proto_response"][sorted(packet_ids['proto_response'].keys())[-1]] + payloads["bad_proto"])
            await writer.drain()
            writer.close()
            return
    else:
        log("- Unexpected packet ID {}. Aborting connection to {}...".format(packet_id,host))
        writer.close()
        return

    try:
        packet_id, data = await asyncio.wait_for(read_packet(reader), timeout=timeout)
    except:
        log("- Lost connection to {}.".format(host))
        writer.close()
        return
    if packet_id == packet_ids["client_connect"][proto]:
        log("- Disconnecting {} with status message and aborting connection.".format(host))
        try:
            sf = open(status_file, 'r')
            status_msg = bytes(sf.read(), 'utf-8')
            sf.close()
        except:
            status_msg = bytes("^white; The server is currently down\n\n^red;(And the pseudoServer"
                               " is misconfigured)", 'utf-8')
            log("! Unable to read status message from {}!".format(status_file))
        vlq = build_signed_VLQ(len(status_msg) + 1)
        length = len(status_msg).to_bytes(1, byteorder='big')
        writer.write(packet_ids["connect_failure"][proto] + vlq + length + status_msg)
        await writer.drain()
        writer.close()
        return
    else:
        log("- Unexpected packet ID {}. Aborting connection to {}...".format(packet_id,host))
        writer.close()
        return


class HandleUDPConnection():
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        host = addr[0]
        log("Datagram received from {}.".format(host))
        try:
            packet_id = data[0:4]
            command_id = data[4:5]
            if packet_id != b'\xff\xff\xff\xff':
                log("- Unexpected packet ID {}.".format(packet_id))
            elif command_id == b'\x54': # A2S_INFO
                payload  = b'\xff\xff\xff\xff' # Packet ID.
                payload += b'\x49' # Header byte.
                payload += b'\x07'# Protocol. ...of something. Completely unrelated to any other version strings, AFAIK.
                payload += bytes(server_name, 'utf-8')
                payload += b'\x00'
                payload += bytes("Unknown", 'utf-8') # Map name. Default when no worlds are loaded.
                payload += b'\x00'
                payload += bytes("starbound", 'utf-8') # Folder. Default for normal installations. Sidenote, WTF? Why would you need to tell people what local folder the game is running in?
                payload += b'\x00'
                payload += bytes("Starbound", 'utf-8') # Game name.
                payload += b'\x00'
                payload += b'\xfe\xff' # This is supposed to be the applications Steam App ID. Except it isn't. It's not the App ID of anything. *shrug*
                payload += b'\x00' # Players online.
                payload += bytes([max_players]) # Maximum players.
                payload += b'\x00' # Bots online.
                payload += b'\x44' # Server type. 'D' for 'Dedicated'
                payload += bytes(operating_sys[0].upper(), 'utf-8') # Environment. 'L' for 'Linux', 'W' for 'Windows', 'M' (or 'O'?) for 'Mac'
                payload += b'\x00' # Visibility.
                payload += b'\x00' # VAC.
                payload += bytes(version, 'utf-8') # Game version.
                payload += b'\x00'
                payload += b'\x80\x00\x00' # This is supposed to be a flag and the server's port number. Again, it isn't... but it's sent even though it's entirely optional.
                # Phew...
                self.transport.sendto(payload, addr)
                log("- Handled A2S_INFO command.")
            elif command_id == b'\x55': # A2S_PLAYER
                payload  = b'\xff\xff\xff\xff' # Packet ID.
                payload += b'\x44' # Header.
                payload += b'\x00' # Players online.
                self.transport.sendto(payload, addr)
                log("- Handled A2S_PLAYER command.")
            elif command_id == b'\x56': # A2S_RULES
                payload  = b'\xff\xff\xff\xff' # Packet ID.
                payload += b'\x45' # Header. NOTE: Docs say this should be b'\x41', but... Starbound.
                payload += b'\x01\x00plugins\x00none\x00' # Default string. Not sure what this is. Mods don't seem to affect it.
                self.transport.sendto(payload, addr)
                log("- Handled A2S_RULES command.")
            elif command_id == b'\x57': # A2S_SERVERQUERY_GETCHALLENGE
                payload  = b'\xff\xff\xff\xff' # Packet ID.
                payload += b'\x41' # Header.
                payload += bytes(random.getrandbits(8) for _ in range(4)) # Challenge. We're not going to pay attention to it later, so there's no need to store it.
                self.transport.sendto(payload, addr)
                log("- Handled A2S_SERVERQUERY_GETCHALLENGE command.")
            else:
                log("- Unknown command id '{}'".format(command_id))
        except Exception as e:
            log("- Malformed datagram.")
            print(e)


def main():
    """
    Start a TCP server and wait for Starbound clients to connect. Upon a successful connection,
    send a compliant response to the client and disconnect it with a status message.
    Before starting the server:
        Expect that all config values are populated.
        Write the PID to pid_file.
    After receiving a SIGTERM:
        Truncate pid_file.
    """
    pid = os.getpid()
    pf = open(pid_file, 'w')
    pf.write(str(pid))
    pf.close()

    loop = asyncio.get_event_loop()
    coro_tcp = asyncio.start_server(handle_tcp_connection, bind_ip, bind_port, loop=loop)
    coro_udp = loop.create_datagram_endpoint(HandleUDPConnection, local_addr=(bind_ip, bind_rq_port))
    server_tcp = loop.run_until_complete(coro_tcp)
    server_udp = loop.run_until_complete(coro_udp)
    log("PID ({}) written to {}".format(pid, pid_file))
    log("Logging to {}".format(log_file))
    log("Listening on {}:{} (TCP) and {}:{} (UDP)".format(bind_ip, bind_port, bind_ip, bind_rq_port))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    print("Shutting down...")
    server_tcp.close()
    server_udp.close()
    loop.run_until_complete(server_tcp.wait_closed())
    loop.run_until_complete(server_udp.wait_closed())
    loop.close()

    pf = open(pid_file, 'w')
    pf.truncate()
    pf.close

if __name__ == '__main__':
    config = configparser.SafeConfigParser()
    try:
        config.read(config_file)
        pid_file      =     config["main"]["pid_file"]
        log_file      =     config["main"]["log_file"]
        status_file   =     config["main"]["status_file"]
        timeout       = int(config["main"]["timeout"])
        bind_port     = int(config["main"]["bind_port"])
        bind_ip       =     config["main"]["bind_ip"]
        bind_rq_port  = int(config["main"]["rquery_port"])
        server_name   =     config["main"]["server_name"]
        version       =     config["main"]["version"]
        max_players   = int(config["main"]["max_players"])
        operating_sys =     config["main"]["operating_system"]
        for option in config["main"]:
            if not config["main"][option]:
                raise ValueError("Config options cannot be null!")
    except Exception as e:
        print("Failed to read {}! Please reference {} for correct syntax."
              "".format(config_file, example_cfg))
        print(e)
        exit(1)
    main()

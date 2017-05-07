#!/usr/bin/python3

"""
A simple Starbound-compatible server designed to function as a quick-n'-dirty fallback.
"""

import asyncio
import configparser
import datetime
import os


config_file = "config/config.cfg"
example_cfg = "config/example.cfg"

packet_ids = {"proto_request":   b'\x00',
              "proto_response":  b'\x01',
              "client_connect":  b'\x0b',
              "connect_failure": b'\x04'}
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


async def handle_connection(reader, writer):
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
    if packet_id == packet_ids["proto_request"]:
        try:
            proto = int.from_bytes(data[2:], byteorder='big')
        except:
            log("- Failed to parse protocol_request protocol ({}). Aborting connection to {}..."
                "".format(data[2:],host))
            writer.close()
            return
        if proto == proto_version:
            log("- Received expected protocol from {}. Continuing...".format(host))
            writer.write(packet_ids["proto_response"] + payloads["good_proto"])
            await writer.drain()
        else:
            log("- Unsupported protocol ({}). Aborting connection to {}...".format(proto,host))
            writer.write(packet_ids["proto_response"] + payloads["bad_proto"])
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
    if packet_id == packet_ids["client_connect"]:
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
        writer.write(packet_ids["connect_failure"] + vlq + length + status_msg)
        await writer.drain()
        writer.close()
        return
    else:
        log("- Unexpected packet ID {}. Aborting connection to {}...".format(packet_id,host))
        writer.close()
        return


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
    coro = asyncio.start_server(handle_connection, bind_ip, bind_port, loop=loop)
    server = loop.run_until_complete(coro)
    log("PID ({}) written to {}".format(pid, pid_file))
    log("Logging to {}".format(log_file))
    log("Listening on {}:{}".format(bind_ip, bind_port))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    print("Shutting down...")
    server.close()
    loop.run_until_complete(server.wait_closed())
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
        proto_version = int(config["main"]["proto_version"])
        timeout       = int(config["main"]["timeout"])
        bind_port     = int(config["main"]["bind_port"])
        bind_ip       =     config["main"]["bind_ip"]
        for option in config["main"]:
            if not config["main"][option]:
                raise ValueError("Config options cannot be null!")
    except Exception as e:
        print("Failed to read {}! Please reference {} for correct syntax."
              "".format(config_file, example_cfg))
        print(e)
        exit(1)
    main()

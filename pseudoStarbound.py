#!/usr/bin/python3

"""
pseudoStarbound - An extremely basic server intended to act as a failover for large Starbound servers.
"""

import asyncio
import datetime
import time

bind_ip = "localhost"
bind_port = 21026
status_file = "status.txt"
cur_proto = 729
timeout = 10

packet_ids = {"proto_request": b'\x00', "proto_response": b'\x01', "client_connect": b'\x0b', "connect_failure": b'\x04'}
payloads = {"good_proto": b'\x02\x01', "bad_proto": b'\x02\x00'} # VLQ (\x02) + True/false.

def log(msg):
    print("{}: {}".format(datetime.datetime.utcnow().isoformat(), msg))

# Shamefully taken from https://github.com/StarryPy/StarryPy3k/ because VLQs suck. :c
def buildSignedVLQ(obj):
    result = bytearray()
    value = abs(int(obj) * 2)
    if obj == 0:
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
def readSignedVLQ(reader):
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
    packet_id = (yield from reader.readexactly(1))
    packet_len = (yield from readSignedVLQ(reader))
    data = (yield from reader.readexactly(abs(packet_len)))
    return packet_id, data


async def handle_connection(reader, writer):
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
            log("- Failed to parse protocolRequest protocol ({}). Aborting connection to {}...".format(data[2:],host))
            writer.close()
            return
        if proto == cur_proto:
            log("- Recieved expected protocol from {}. Continuing...".format(host))
            writer.write(packet_ids["proto_response"] + payloads["good_proto"])
            await writer.drain()
        else:
            log("- Unsupported protocol ({}). Aborting connection to {}...".format(proto,host))
            writer.write(packet_ids["proto_response"] + payloads["bad_proto"])
            await writer.drain()
            writer.close()
            return
    else:
        log("- Unepected packet ID {}. Aborting connection to {}...".format(packet_id,host))
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
            # Why open, read, and close the file every connection? It's often re-written by other utilities and this tends to break stuff.
            # This may seem inefficient, but I've tested it with ~1000 protocol-compliant client connections per second and experienced no issues.
            f = open(status_file, 'r')
            status_msg = bytes(f.read(), 'utf-8')
        except:
            status_msg = bytes("^white; The server is currently down\n\n^red;(And the pseudoServer is misconfigured)", 'utf-8')
            log("! Unable to read status message from {}!".format(status_file))
        vlq = buildSignedVLQ(len(status_msg) + 1)
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
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_connection, bind_ip, bind_port, loop=loop)
    server = loop.run_until_complete(coro)
    print("Listening on {}:{}.".format(bind_ip, bind_port))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    print("Shutting down...")
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()

if __name__ == '__main__':
    main()

#!/usr/bin/env python3

import asyncio
import struct
import socket
import logging

# Setup logger 
logger = logging.getLogger('Socks5')
logger.setLevel(logging.DEBUG)
logging.basicConfig(level=logging.DEBUG, format='%(threadName)s %(asctime)s- %(levelname)s - %(message)s')

class RemoteHost(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        self.server.write(data)

    def connection_lost(self, *args):
        self.server.close()

async def socks5_handler(reader, writer):
    SOCKS5_VER = 0x05
    SOCKS5_NOAUTH = 0x00
    SOCKS5_CONNECT = 0x01
    SOCKS5_DOMAINNAME = 0x03
    SOCKS5_IPV4 = 0x01
    SOCKS5_IPV6 = 0x02
    SOCKS5_SUCCEEDED = 0x00
    BUF_SIZE = 4096

    async def read_unpack(format, size):
        return struct.unpack(format, await reader.read(size))
    
    def write_pack(*argv):
        writer.write(struct.pack(*argv))

    # Authentication negotiations
    ver, nmeth = await read_unpack('!BB',2)
    assert SOCKS5_VER == ver

    # Request details
    meth = await reader.read(nmeth)
    write_pack('!BB', SOCKS5_VER, SOCKS5_NOAUTH)

    # Implement CONNECT only
    ver, cmd, rsv, atyp = await read_unpack('!BBBB',4)
    assert ver == SOCKS5_VER and cmd == SOCKS5_CONNECT

    host = ''
    if SOCKS5_IPV4 == atyp:
        addr = await reader.read(4)
        host = socket.inet_ntop(addr)
    
    elif SOCKS5_IPV6 == atyp:
        addr = await reader.read(16)
        host = socket.inet_ntop(addr)

    elif SOCKS5_DOMAINNAME == atyp:
        length = (await read_unpack('!B', 1))[0]
        addr = await reader.read(length)
        host = socket.gethostbyname(addr)

    else:
        raise AssertionError('Error: Invalid atyp')
    
    # Read port and address
    port = (await read_unpack('!H', 2))[0]
    addr = struct.unpack('!I',socket.inet_aton(host))[0]

    # Create connection
    transport, remote = await loop.create_connection(RemoteHost, host, port)
    remote.server = writer

    # Replies - completed the authentication negotiations
    write_pack('!BBBBIH', SOCKS5_VER, SOCKS5_SUCCEEDED, 0x00, SOCKS5_IPV4, addr, port)

    # Pipe between client and server
    data = await reader.read(BUF_SIZE)
    while data:
        remote.transport.write(data)
        data = await reader.read(BUF_SIZE)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(socks5_handler, '127.0.0.1', 8888, loop=loop)
    server = loop.run_until_complete(coro)
    logging.debug('Serving on {}'.format(server.sockets[0].getsockname()))
    
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
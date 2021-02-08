# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import platform
import socket

import sctp


host = '::'
port = 9090

sock = sctp.sctpsocket_tcp(socket.AF_INET6)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
sock.bind((host, port))
sock.listen(1)

while True:
    # wait for a connection
    connection, client_address = sock.accept()

    try:
        while True:
            data = connection.recv(1024)
            if data:
                # send response to client.
                response = '%s: HELLO, I AM ALIVE!!!' % platform.node()
                sent = connection.send(response.encode('utf-8'))
            else:
                # no more data -- quit the loop
                break
    finally:
        # Clean up the connection
        connection.close()

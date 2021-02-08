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

import socket
import sys

import sctp


def connect_plus_message(out_ip, out_port):
    for res in socket.getaddrinfo(out_ip, out_port, socket.AF_UNSPEC,
                                  socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
        addr_fam, socktype, proto, canonname, sa = res
        try:
            sock = sctp.sctpsocket_tcp(addr_fam)
        except OSError:
            sock = None
            continue
        try:
            sock.connect(sa)
        except OSError:
            sock.close()
            sock = None
            continue
        break

    if sock:
        print("Sending Message")
        sock.sctp_send(msg='HELLO, I AM ALIVE!!!')
        msg_from_server = sock.recvfrom(1024)
        print(msg_from_server[0].decode('utf-8'))
        sock.shutdown(0)
        sock.close()


if __name__ == '__main__':
    connect_plus_message(sys.argv[1], int(sys.argv[2]))

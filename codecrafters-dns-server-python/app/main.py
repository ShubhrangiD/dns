import socket
import struct
from dataclasses import dataclass
@dataclass
class DnsHeader:
    class Header:
        id: int
        qr: int
        opcode: int
        aa: int
        tc: int
        rd: int
        ra: int
        z: int
        rcode: int
        qdcount: int
        ancount: int
        nscount: int
        arcount: int
    @property
    def as_bytes(self) -> bytes:
        flag_a = self.qr << 7 | self.opcode << 3 | self.aa << 2 | self.tc << 1 | self.rd
        flag_b = self.ra << 7 | self.z << 4 | self.rcode
        return struct.pack(
            ">HBBHHHH",
            self.id,
            flag_a,
            flag_b,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )
def create_header(msg: DnsHeader) -> bytes:
@dataclass
class Question:
    name: str
    typ: int
    cls: int
    @property
    def as_bytes(self) -> bytes:
        byte_arr = bytearray()
        for part in self.name.split("."):
            byte_arr.extend(len(part).to_bytes(1, "big"))
            byte_arr.extend(part.encode())
        byte_arr.extend((0).to_bytes(1, "big"))

        return byte_arr + struct.pack(">HH", self.typ, self.cls)
@dataclass
class DnsMessage:
    header: Header
    question: Question
    @property
    def as_bytes(self) -> bytes:
        return self.header.as_bytes + self.question.as_bytes
def create_header(msg: Header) -> bytes:
    flag_a = msg.qr << 7 | msg.opcode << 3 | msg.aa << 2 | msg.tc << 1 | msg.rd
    flag_b = msg.ra << 7 | msg.z << 4 | msg.rcode
    return struct.pack(
        ">HBBHHHH",
        msg.id,
        flag_a,
        flag_b,
        msg.qdcount,
        msg.ancount,
        msg.nscount,
        msg.arcount,
    )
def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            msg = DnsHeader(1234, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            response = create_header(msg)
            header = Header(
                id=1234,
                qr=1,
                opcode=0,
                aa=0,
                tc=0,
                rd=0,
                ra=0,
                z=0,
                rcode=0,
                qdcount=1,
                ancount=0,
                nscount=0,
                arcount=0,
            )
            
            question = Question(name="codecrafters.io", typ=1, cls=1)
            msg = DnsMessage(header, question)
            udp_socket.sendto(response, source)
            udp_socket.sendto(msg.as_bytes, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break
if __name__ == "__main__":
    main()
import sys
import os
import enum
import struct
from array import *
lastpacket = 0


class TftpProcessor(object):

    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):
        self.packet_buffer = []

    def process_udp_packet(self, packet_data, uploadedfile=None):

        DATA, opcode, len = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(DATA, uploadedfile, opcode, len)
        if(out_packet != 0):
            self.packet_buffer.append(out_packet)

    # Analysis of the packet to know its type

    def _parse_udp_packet(self, packet_bytes):
        opcode = struct.unpack("!bb", packet_bytes[:2])
        obj = TftpProcessor()
        if (opcode[1] == obj.TftpPacketType.ACK.value):
            blockNumber = struct.unpack("!bb", packet_bytes[2:4])
            newblock = blockNumber[1] + 1
            return newblock, opcode[1], 0
        elif (opcode[1] == obj.TftpPacketType.DATA.value):
            block_num = struct.unpack("!bb", packet_bytes[2:4])
            lengthofDataPacket = len(packet_bytes[4:])
            return block_num[1], opcode[1], lengthofDataPacket
        elif (opcode[1] == obj.TftpPacketType.ERROR.value):
            error_code = struct.unpack("!bb", packet_bytes[2:4])[1]
            print("error code >> ", error_code)
            myformat = "!" + \
                str(len(packet_bytes[4:len(packet_bytes) - 1])) + "s"
            error_msg = struct.unpack(
                myformat, packet_bytes[4:len(packet_bytes) - 1])
            print("Error msg >> ", error_msg[0].decode("UTF-8"))
            sys.exit(error_code)

    def _do_some_logic(self, DATA, uploadedfile, op_code, length=None):

        obj = TftpProcessor()
        if op_code == obj.TftpPacketType.ACK.value:
            myformat = "!H" + "H"
            bytepacket = struct.pack(myformat, 3, DATA)
            i = 0
            blockindex = DATA - 1
            while (i < len(uploadedfile[blockindex])):
                bytepacket += struct.pack("!B", uploadedfile[blockindex][i])
                i = i + 1
            if (len(bytepacket) == 4):
                return 0
            else:
                return bytepacket
        elif op_code == obj.TftpPacketType.DATA.value:
            global lastpacket
            if (lastpacket == 0):
                myformat = "!HH"
                blocknum = DATA
                bytepacket = struct.pack(myformat, 4, blocknum)
                if (length != 512):
                    lastpacket = 1
                    return bytepacket
                return bytepacket
            else:
                return 0

    def write_file(self, file_chuncks, file_name):
        file = open(file_name, "a")
        dataBybyte = file_chuncks[4:]
        s = str(dataBybyte, 'utf-8')
        file.write(s)
        file.close()

    def get_next_output_packet(self):
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):
        "generating read request"
        obj = TftpProcessor()
        opcode = obj.TftpPacketType.RRQ.value
        filename = file_path_on_server
        mode = "octet"
        filenameLength = len(filename)
        modeLength = len(mode)
        myformat = "!H" + str(filenameLength) + "s" + \
            "?" + str(modeLength) + "s" + "?"
        request_p = struct.pack(myformat, opcode, filename.encode(
            "ASCII"), 0, mode.encode("ASCII"), 0)
        return request_p

    def upload_file(self, file_path_on_server):
        request = ""
        obj = TftpProcessor()
        opcode = obj.TftpPacketType.WRQ.value
        print("request : ", request)
        filename = file_path_on_server
        mode = "octet"
        filenameLength = len(filename)
        modeLength = len(mode)
        myformat = "!" + "H" + str(filenameLength) + \
            "s" + "B" + str(modeLength) + "s" + "B"
        print("write request : ", request)
        request_p = struct.pack(myformat, opcode, filename.encode(
            "ASCII"), 0, mode.encode("ASCII"), 0)
        print(list(request_p))
        "request_string into request_bytes"
        return request_p


"""""""""""""""""""""""""""""""""""""""""""" "END OF CLASS" """"""""""""""""""""""""""""""""""""""""""""""""


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")


def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.
    Feel free to delete this function.
    """
    import socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, 69)
    return client_socket, server_address


def parse_user_input(address, operation, file_name=None):
    obj = TftpProcessor()
    mysock, myIPadress = setup_sockets(address)
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        data = []
        totaldata = []
        with open(file_name, 'rb') as f:
            size = 512
            count = 0
            data = (f.read(size))
            totaldata.append(data)
            while len(data) > 0:
                count = count + 1
                print(count)
                data = f.read(size)
                totaldata.append(data)
        packet = obj.upload_file(file_name)
        mysock.sendto(packet, myIPadress)
        recpacket, newport = mysock.recvfrom(516)
        obj.process_udp_packet(recpacket, totaldata)
        while(obj.has_pending_packets_to_be_sent()):
            mysock.sendto(obj.get_next_output_packet(), newport)
            recpacket, newport = mysock.recvfrom(4)
            obj.process_udp_packet(recpacket, totaldata)
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        read_request = obj.request_file(file_name)
        mysock.sendto(read_request, myIPadress)
        print("sent read request to server...")
        print("waiting for server to send the file...")
        print("begining data downloading..")
        recpacket, newport = mysock.recvfrom(516)
        obj.process_udp_packet(recpacket)
        obj.write_file(recpacket, file_name)
        while (obj.has_pending_packets_to_be_sent()):
            mysock.sendto(obj.get_next_output_packet(), newport)
            if (lastpacket == 1):
                break
            recpacket, newport = mysock.recvfrom(516)
            obj.write_file(recpacket, file_name)
            obj.process_udp_packet(recpacket)
            print("Download finished")


def get_arg(param_index, default=None):
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def main():
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)
    ip_address = get_arg(1)
    operation = get_arg(2)
    file_name = get_arg(3)
    print("ip_address is : ", ip_address)
    print("operation is : ", operation)
    print("file_name is : ", file_name)
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()

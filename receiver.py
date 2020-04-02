from socket import *
import pickle
import time
import hashlib
import sys

class Packet:
    def __init__(self, seqNum=None, ackNum=None, MSS=None, checkSum=None, SYN=None, ACK=None, FIN=None, payLoad=None):
        self.seqNum = seqNum
        self.ackNum = ackNum
        self.MSS = MSS
        self.checkSum = checkSum
        self.SYN = SYN
        self.ACK = ACK
        self.FIN = FIN
        self.payLoad = payLoad


def write_receiver_log(event, t, packet):
    global log
    global program_start_time

    if t is None:
        t = time.time() - program_start_time
    seqNum = packet.seqNum
    data_bytes = len(packet.payLoad)
    ackNum = packet.ackNum

    if packet.FIN:
        packet_type = 'F'
    elif packet.SYN and packet.ACK:
        packet_type = 'SA'
    elif packet.SYN:
        packet_type = 'S'
    elif packet.ACK:
        packet_type = 'A'
    else:
        packet_type = 'D'

    print("{:<10}{:10.2f}{:>10}{:>20}{:>20}{:>20}".format(event, t, packet_type, seqNum, data_bytes, ackNum), file=log)
    print("{:<10}\t{:<25}\t{:<5}\t{:>10}\t{:>10}\t{:>10}".format(event, t, packet_type, seqNum, data_bytes, ackNum))


def is_packets_in_ordered(buffer):
    sequence = sorted(buffer.keys())
    for i in range(len(sequence[:-1])):
        if sequence[i] + len(buffer[sequence[i]].payLoad) != sequence[i+1]:
            return False
    return True


def ack_out_of_order_buffer(buffer):
    sequence = sorted(buffer.keys())
    for i in range(len(sequence[:-1])):
        if sequence[i] + len(buffer[sequence[i]].payLoad) != sequence[i + 1]:
            return sequence[i] + len(buffer[sequence[i]].payLoad)


def receiving_file():
    global receiverSocket
    global statistics
    global pdf_file
    global program_start_time


    lastAck = None
    buffer = {}
    while True:
        data, addr = receiverSocket.recvfrom(4096)
        packet = pickle.loads(data)
        statistics['totalSegmentReceived'] += 1
        statistics['totalDataReceived'] += len(packet.payLoad)

        if packet.SYN:
            program_start_time = time.time()
            write_receiver_log('rcv', None, packet)
            lastAck = initial_connection(packet, addr)
        elif packet.FIN:
            write_receiver_log('rcv', None, packet)
            close_connection(packet, addr)
            break
        elif packet.ACK:
            write_receiver_log('rcv', None, packet)
        else:
            statistics['totalDataSegmentReceived'] += 1
            check_sum = hashlib.md5(packet.payLoad).hexdigest()
            if check_sum != packet.checkSum:
                statistics['dataSegmentCorr'] += 1
                write_receiver_log('rcv/corr', None, packet)
            else:
                # payLoad is correct
                if packet.seqNum > lastAck:
                    if packet.seqNum not in buffer:
                        buffer[packet.seqNum] = packet
                    else:
                        statistics['dupSegmentReceived'] += 1
                    write_receiver_log('rcv', None, packet)
                    send_Ack('snd/DA', lastAck, addr)
                elif packet.seqNum < lastAck:
                    statistics['dupSegmentReceived'] += 1
                    write_receiver_log('rcv', None, packet)
                    send_Ack('snd/DA', lastAck, addr)
                else:
                    # if packet.seqNum == lastAck
                    if not buffer:
                        # receive segment as expected
                        write_receiver_log('rcv', None, packet)
                        pdf_file.write(packet.payLoad)

                        lastAck += len(packet.payLoad)
                        send_Ack('snd', lastAck, addr)
                    else:
                        # if buffer is not empty
                        if packet.seqNum in buffer:
                            statistics['dupSegmentReceived'] += 1
                        else:
                            buffer[packet.seqNum] = packet
                        if is_packets_in_ordered(buffer):

                            for seq in sorted(buffer.keys()):
                                pdf_file.write(buffer[seq].payLoad)

                            lastSeqNum = sorted(buffer.keys())[-1]
                            lastAck = lastSeqNum + len(buffer[lastSeqNum].payLoad)
                            buffer = {}
                            write_receiver_log('rcv', None, packet)
                            send_Ack('snd', lastAck, addr)
                        else:
                            write_receiver_log('rcv', None, packet)
                            if lastAck in buffer:
                                lastAck = ack_out_of_order_buffer(buffer)
                                send_Ack('snd', lastAck, addr)
                            else:
                                send_Ack('snd/DA', lastAck, addr)


def send_Ack(type, ackNum, addr):
    global receiverSocket
    global statistics
    if type == 'snd/DA':
        statistics['dupAckSent'] += 1
    packet = Packet(seqNum=1, ackNum=ackNum, SYN=0, ACK=1, FIN=0, payLoad='')
    receiverSocket.sendto(pickle.dumps(packet), addr)
    write_receiver_log(type, None, packet)


def initial_connection(packet, addr):
    global receiverSocket
    packet = Packet(seqNum=0, ackNum=packet.seqNum + 1, MSS=packet.MSS, checkSum=0, SYN=1, ACK=1, FIN=0, payLoad='')
    receiverSocket.sendto(pickle.dumps(packet), addr)
    write_receiver_log('snd', None, packet)
    return packet.ackNum


def close_connection(packet, addr):
    global receiverSocket
    global statistics
    # send FIN ACK
    packet = Packet(seqNum=packet.ackNum, ackNum=packet.seqNum + 1, MSS=packet.MSS, checkSum=0, SYN=0, ACK=1, FIN=0,
                    payLoad='')
    receiverSocket.sendto(pickle.dumps(packet), addr)
    write_receiver_log('snd', None, packet)

    # send FIN
    # packet = Packet(seqNum=packet.ackNum, ackNum=packet.seqNum + 1, MSS=packet.MSS, checkSum=0, SYN=0, ACK=0, FIN=1,
    #                 payLoad='')
    packet.ACK = 0
    packet.FIN = 1
    receiverSocket.sendto(pickle.dumps(packet), addr)
    write_receiver_log('snd', None, packet)

    while True:
        data, addr = receiverSocket.recvfrom(4096)
        packet = pickle.loads(data)
        statistics['totalSegmentReceived'] += 1
        write_receiver_log('rcv', None, packet)
        if packet.ACK:
            break


def print_statistics():
    global log
    global statistics
    print('==============================================', file=log)
    print('{:<35} \t{:>10}'.format('Amount of data received (bytes)', statistics['totalDataReceived']), file=log)
    print('{:<35} \t{:>10}'.format('Total Segments Received', statistics['totalSegmentReceived']), file=log)
    print('{:<35} \t{:>10}'.format('Data segments received', statistics['totalDataSegmentReceived']), file=log)
    print('{:<35} \t{:>10}'.format('Data segments with Bit Errors', statistics['dataSegmentCorr']), file=log)
    print('{:<35} \t{:>10}'.format('Duplicate data segments received', statistics['dupSegmentReceived']), file=log)
    print('{:<35} \t{:>10}'.format('Duplicate ACKs sent', statistics['dupAckSent']), file=log)
    print('==============================================', file=log)


if __name__ == '__main__':
    port_number = int(sys.argv[1])
    file_name = sys.argv[2]

    receiverSocket = socket(AF_INET, SOCK_DGRAM)
    receiverSocket.bind(('', port_number))
    log = open('Receiver_log.txt', 'w')
    program_start_time = None
    statistics = {'totalDataReceived': 0,
                  'totalSegmentReceived': 0,
                  'totalDataSegmentReceived': 0,
                  'dataSegmentCorr': 0,
                  'dupSegmentReceived': 0,
                  'dupAckSent': 0}


    pdf_file = open(file_name, 'wb')
    receiving_file()
    print_statistics()
    log.close()
    pdf_file.close()






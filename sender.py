import threading
from socket import *
import pickle
import time
import hashlib
from collections import defaultdict
import sys
import random
import copy


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


class Pld:
    def __init__(self, socketName):
        self.pDrop = 0 if sys.argv[7] == '0' else float(sys.argv[7])
        self.pDup = 0 if sys.argv[8] == '0' else float(sys.argv[8])
        self.pCorr = 0 if sys.argv[9] == '0' else float(sys.argv[9])
        self.pRord = 0 if sys.argv[10] == '0' else float(sys.argv[10])
        self.maxOrder = int(sys.argv[11])
        self.pDelay = 0 if sys.argv[12] == '0' else float(sys.argv[12])
        self.maxDelay = int(sys.argv[13])
        self.seed = int(sys.argv[14])
        self.segmentSentAfterReorder = -1
        self.needReorder = False
        self.reOrderPacket = None
        self.clientSocket = socketName
        self.delayKey = 0
        random.seed(self.seed)

    def send(self, packet, address, RXT=0):
        global statistics
        global lastAck
        global pldDelayPackets

        if self.pDrop != 0 and random.random() < self.pDrop:
            write_sender_log('drop', None, packet)

        elif self.pDup !=0 and random.random() < self.pDup:
            self.clientSocket.sendto(pickle.dumps(packet), address)
            write_sender_log('snd', None, packet)
            self.clientSocket.sendto(pickle.dumps(packet), address)
            write_sender_log('snd/dup', None, packet)

        elif self.pCorr != 0 and random.random() < self.pCorr:
            corrPayLoad = bytearray(packet.payLoad)
            ranIndex = random.randint(0,len(corrPayLoad)-1)
            corrPayLoad[ranIndex] ^= 1
            corrPacket = copy.deepcopy(packet)
            corrPacket.payLoad = bytes(corrPayLoad)
            self.clientSocket.sendto(pickle.dumps(corrPacket), address)
            write_sender_log('snd/corr', None, packet)

        elif self.pRord != 0 and random.random() < self.pRord:
            if self.needReorder:
                self.clientSocket.sendto(pickle.dumps(packet), address)
                write_sender_log('snd', None, packet)
            else:
                self.needReorder = True
                self.reOrderPacket = packet

        elif self.pDelay != 0 and random.random() < self.pDelay:
            self.delayKey += 1
            pldDelayPackets[self.delayKey] = {'delayPacket': packet,
                                              'startTime': time.time(),
                                              'timeoutInterval': random.randint(0,self.maxDelay) / 1000}

        else:
            self.clientSocket.sendto(pickle.dumps(packet), address)
            if RXT:
                write_sender_log('snd/RXT', None, packet)
            else:
                write_sender_log('snd', None, packet)

        if self.needReorder:
            # reorder packet does not count itself
            self.segmentSentAfterReorder += 1
            if self.segmentSentAfterReorder == self.maxOrder:
                self.clientSocket.sendto(pickle.dumps(self.reOrderPacket), address)

                # bug here but fixed, should be self.reOrderPacket not packet
                write_sender_log('snd/rord', None, self.reOrderPacket)
                self.reOrderPacket = None
                self.segmentSentAfterReorder = -1
                self.needReorder = False


def split_file(file, c_isn, MSS):
    try:
        with open(file, "rb") as read_file:
            binary_file = read_file.read()
            file_size = len(binary_file)
            if file_size == 0:
                file_segments = {c_isn+1: ""}
            else:
                file_segments = {c_isn + 1 + i: binary_file[i:i + MSS] for i in range(0, file_size, MSS)}
            return file_segments, file_size
    except FileNotFoundError:
        print("{} not found!".format(file))


def write_sender_log(event, t, packet):
    global log
    global program_start_time
    global statistics

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

    if packet_type == 'D':
        statistics['totalSegmentPLD'] += 1

    if event == 'snd':
        statistics['totalSegmentsTransmitted'] += 1
    elif event == 'snd/corr':
        statistics['totalSegmentsCorr'] += 1
        statistics['totalSegmentsTransmitted'] += 1
    elif event == 'snd/dup':
        statistics['totalSegmentsDup'] += 1
        statistics['totalSegmentsTransmitted'] += 1
    elif event == 'snd/dely':
        statistics['totalSegmentsDelay'] += 1
        statistics['totalSegmentsTransmitted'] += 1
    elif event == 'drop':
        statistics['totalSegmentsDropped'] += 1
        statistics['totalSegmentsTransmitted'] += 1
    elif event == 'snd/rord':
        statistics['totalSegmentsReorder'] += 1
        statistics['totalSegmentsTransmitted'] += 1
    elif event == 'snd/RXT':
        statistics['totalSegmentsTransmitted'] += 1
    elif event == 'rcv/DA':
        statistics['totalDupAcks'] += 1

    print("{:<10}{:10.2f}{:>10}{:>20}{:>20}{:>20}".format(event, t, packet_type, seqNum, data_bytes, ackNum), file=log)
    print("{:<10}\t{:<25}\t{:<5}\t{:>10}\t{:>10}\t{:>10}".format(event, t, packet_type, seqNum, data_bytes, ackNum))


def compute_RTO(sampleRTT):
    global DevRTT
    global EstimatedRTT
    global sender_timeout_interval
    global gamma

    alpha = 0.125
    beta = 0.25
    EstimatedRTT = (1 - alpha) * EstimatedRTT + alpha * sampleRTT
    DevRTT = (1 - beta) * DevRTT + beta * abs(sampleRTT - EstimatedRTT)
    sender_timeout_interval = EstimatedRTT + gamma * DevRTT



def receiving_thread():
    global clientSocket
    global lock
    global sender_timer
    global rcv_packet
    global state
    global statistics
    global file_size
    global lastAck
    global sent_data_packs
    global lastSegmentAlreadySent

    packet_acked = defaultdict(int)
    packet_acked[lastAck] = 0

    while True:
        data, address = clientSocket.recvfrom(4096)
        with lock:
            rcv_packet = pickle.loads(data)
            if rcv_packet.ackNum == lastAck and lastAck in sent_data_packs:
                packet_acked[rcv_packet.ackNum] += 1

            if rcv_packet.ackNum <= lastAck and not rcv_packet.FIN:
                write_sender_log('rcv/DA', None, rcv_packet)
            else:
                write_sender_log('rcv', None, rcv_packet)

            if state == 'ACTIVE':
                if rcv_packet.ackNum > file_size:
                    lastAck = rcv_packet.ackNum
                    state = 'FIN'
                elif rcv_packet.ackNum > lastAck:
                    if sender_timer is not None:
                        if 0 < rcv_packet.ackNum - sender_timer['seqNum'] <= MSS:
                            if sender_timer['isValidRTT']:
                                RTT = time.time() - sender_timer['startTime']
                                compute_RTO(RTT)
                        if rcv_packet.ackNum > sender_timer['seqNum'] and not lastSegmentAlreadySent:
                            sender_timer = None
                    lastAck = rcv_packet.ackNum


                elif packet_acked[rcv_packet.ackNum] == 3:
                    PLD.send(sent_data_packs[lastAck], address, RXT=1)
                    statistics['totalFastRXT'] += 1

                    # reset ackNum for fast-retransmit and if receive triple dup-ack again, fast-retransmit again
                    packet_acked[rcv_packet.ackNum] = 0
                    if sender_timer is not None:
                        sender_timer['isValidRTT'] = False

            if state == 'FIN':
                # send FIN
                lastAck = rcv_packet.ackNum
                packet = Packet(seqNum=rcv_packet.ackNum, ackNum=rcv_packet.seqNum, MSS=MSS, checkSum=0, SYN=0,
                                ACK=0, FIN=1, payLoad='')
                clientSocket.sendto(pickle.dumps(packet), receiverAddress)
                write_sender_log('snd', None, packet)
                state = 'FIN_WAITE'

            if state == 'FIN_WAITE':
                lastAck = rcv_packet.ackNum
                if rcv_packet.FIN:
                    # send FIN ACK
                    packet = Packet(seqNum=rcv_packet.ackNum, ackNum=rcv_packet.seqNum + 1, MSS=MSS, checkSum=0, SYN=0,
                                    ACK=1, FIN=0, payLoad='')
                    clientSocket.sendto(pickle.dumps(packet), receiverAddress)
                    write_sender_log('snd', None, packet)
                    break


def sending_thread():
    global clientSocket
    global receiverAddress
    global state
    global MSS
    global rcv_packet
    global lastAck
    global MWS
    global file_size
    global PLD
    global file_segments
    global statistics
    global sender_timer
    global sent_data_packs
    global lastSeqNum
    global lastSegmentAlreadySent

    next_seq_num = rcv_packet.ackNum

    while state == 'ACTIVE':
        if next_seq_num - lastAck < MWS and next_seq_num <= file_size:
            with lock:
                if rcv_packet.seqNum == 0:
                    ack_num = rcv_packet.seqNum + 1
                else:
                    ack_num = rcv_packet.seqNum + len(rcv_packet.payLoad)  # rcv_packet.payLoad is always 0
                check_sum = hashlib.md5(file_segments[next_seq_num]).hexdigest()
                pay_load = file_segments[next_seq_num]
                packet = Packet(seqNum=next_seq_num, ackNum=ack_num, MSS=MSS, checkSum=check_sum, SYN=0, ACK=0, FIN=0, payLoad=pay_load)

                sent_data_packs[next_seq_num] = packet
                PLD.send(packet, receiverAddress, RXT=0)
                if sender_timer is None:
                    sender_timer = {'seqNum': packet.seqNum,
                                    'startTime': time.time(),
                                    'isValidRTT': True}

                if next_seq_num == lastSeqNum:
                    lastSegmentAlreadySent = True
                    break

                next_seq_num += MSS


def sender_timer_thread():
    global sender_timer
    global lock
    global sender_timeout_interval
    global lastAck
    global state
    global sent_data_packs
    global statistics

    while state == 'ACTIVE':
        with lock:
            if sender_timer is not None and (time.time() - sender_timer['startTime'] > sender_timeout_interval):
                statistics['totalTimeoutRXT'] += 1
                if lastAck in sent_data_packs:
                    PLD.send(sent_data_packs[lastAck], receiverAddress, RXT=1)
                sender_timer['isValidRTT'] = False
                sender_timer['startTime'] = time.time()



def PLD_timer_thread():
    global state
    global pldDelayPackets
    global lock
    global receiverAddress

    while state == 'ACTIVE':
        with lock:
            for k in list(pldDelayPackets.keys()):
                if time.time() - pldDelayPackets[k]['startTime'] > pldDelayPackets[k]['timeoutInterval']:
                    clientSocket.sendto(pickle.dumps(pldDelayPackets[k]['delayPacket']), receiverAddress)
                    write_sender_log('snd/dely', None, pldDelayPackets[k]['delayPacket'])
                    del pldDelayPackets[k]


def initial_connection():
    global clientSocket
    global receiverAddress
    global state
    global rcv_packet
    global lastAck
    global MSS

    # send SYN to reveiver
    packet = Packet(seqNum=0, ackNum=0, MSS=MSS, checkSum=0, SYN=1, ACK=0, FIN=0, payLoad='')
    clientSocket.sendto(pickle.dumps(packet), receiverAddress)
    write_sender_log('snd', None, packet)

    # waite for SYN
    data, address = clientSocket.recvfrom(4096)
    rcv_packet = pickle.loads(data)
    receive_time = time.time() - program_start_time
    if rcv_packet.SYN and rcv_packet.ACK:
        write_sender_log('rcv', receive_time, rcv_packet)

        # send SYN ACK
        packet = Packet(seqNum=rcv_packet.ackNum, ackNum=rcv_packet.seqNum + 1, MSS=MSS, checkSum=0, SYN=0, ACK=1,
                        FIN=0, payLoad='')
        clientSocket.sendto(pickle.dumps(packet), receiverAddress)
        write_sender_log('snd', None, packet)
        lastAck = rcv_packet.ackNum
        state = 'ACTIVE'
        return True
    else:
        return False


def print_statistics():
    global statistics
    global log
    global file_size

    print('=============================================================', file=log)
    print('{:<45} \t{:>10}'.format('Size of the file (in Bytes)',file_size), file=log)
    print('{:<45} \t{:>10}'.format('Segments transmitted (including drop & RXT)', statistics['totalSegmentsTransmitted']), file=log)
    print('{:<45} \t{:>10}'.format('Number of Segments handled by PLD', statistics['totalSegmentPLD']), file=log)
    print('{:<45} \t{:>10}'.format('Number of Segments dropped', statistics['totalSegmentsDropped']), file=log)
    print('{:<45} \t{:>10}'.format('Number of Segments Corrupted', statistics['totalSegmentsCorr']), file=log)
    print('{:<45} \t{:>10}'.format('Number of Segments Re-ordered', statistics['totalSegmentsReorder']), file=log)
    print('{:<45} \t{:>10}'.format('Number of Segments Duplicated', statistics['totalSegmentsDup']), file=log)
    print('{:<45} \t{:>10}'.format('Number of Segments Delayed', statistics['totalSegmentsDelay']), file=log)
    print('{:<45} \t{:>10}'.format('Number of Retransmissions due to TIMEOUT', statistics['totalTimeoutRXT']), file=log)
    print('{:<45} \t{:>10}'.format('Number of FAST RETRANSMISSION', statistics['totalFastRXT']), file=log)
    print('{:<45} \t{:>10}'.format('Number of DUP ACKS received', statistics['totalDupAcks']), file=log)
    print('=============================================================', file=log)


if __name__ == '__main__':

    clientSocket = socket(AF_INET, SOCK_DGRAM)

    receiverAddress = (sys.argv[1], int(sys.argv[2]))
    file_name, MWS, MSS, gamma = sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
    EstimatedRTT = 0.5
    DevRTT = 0.25
    sender_timeout_interval = EstimatedRTT + gamma * DevRTT
    c_isn = 0

    lastAck = None
    sender_timer = None
    log = open('Sender_log.txt', 'w')
    state = 'CLOSED'

    statistics = {'totalSegmentsTransmitted': 0,
                  'totalSegmentPLD': 0,
                  'totalTimeout': 0,
                  'totalSegmentsDropped': 0,
                  'totalSegmentsCorr': 0,
                  'totalSegmentsReorder': 0,
                  'totalSegmentsDup': 0,
                  'totalSegmentsDelay': 0,
                  'totalTimeoutRXT': 0,
                  'totalFastRXT': 0,
                  'totalDupAcks': 0}

    sent_data_packs = {}
    rcv_packet = Packet()
    PLD = Pld(clientSocket)


    program_start_time = time.time()
    pldDelayPackets = {}

    if not initial_connection():
        print('Connection initialisation failed!')
        exit(1)

    file_segments, file_size = split_file(file_name, c_isn, MSS)
    lastSeqNum = (file_size // MSS) * MSS + c_isn + 1
    lastSegmentAlreadySent = False

    lock = threading.Lock()
    rcv_t = threading.Thread(target=receiving_thread)
    snd_t = threading.Thread(target=sending_thread)
    tim_t = threading.Thread(target=sender_timer_thread)
    pld_tim_t = threading.Thread(target=PLD_timer_thread)
    rcv_t.start()
    snd_t.start()
    tim_t.start()
    pld_tim_t.start()
    rcv_t.join()
    snd_t.join()
    tim_t.join()
    pld_tim_t.join()

    print_statistics()
    

    log.close()
    exit(0)








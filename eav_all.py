import asyncio
import playground
import logging

import functools
import random
import zlib

from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.packet.fieldtypes import UINT8, UINT16, UINT32, UINT64, LIST, BUFFER, STRING, BOOL
from playground.network.packet import PacketType
from playground.common import CustomConstant as Constant


# logging.getLogger().setLevel(logging.NOTSET)
# logging.getLogger().addHandler(logging.StreamHandler())

class PEEPPacket(PacketType):
    DEFINITION_IDENTIFIER = 'PEEP.Packet'
    DEFINITION_VERSION = '1.0'

    FIELDS = [
        ('Type', UINT8),
        ('SequenceNumber', UINT32({Optional: True})),
        ('Checksum', UINT16),
        ("Acknowledgement", UINT32({Optional: True})),
        ("Data", BUFFER({Optional: True}))
    ]

    # Type
    SYN = Constant(intValue=0, strValue='SYN')
    SYN_ACK = Constant(intValue=1, strValue='SYN-ACK')
    ACK = Constant(intValue=2, strValue='ACK')
    RIP = Constant(intValue=3, strValue='RIP')
    RIP_ACK = Constant(intValue=4, strValue='RIP-ACK')
    DATA = Constant(intValue=5, strValue='DATA')

    PACKET_TYPES = [SYN, SYN_ACK, ACK, RIP_ACK, DATA]

    def calculateChecksum(self):
        original_checksum = self.Checksum
        self.Checksum = 0
        bytes = self.__serialize__()
        self.Checksum = original_checksum
        return zlib.adler32(bytes) & 0xffff

    def updateChecksum(self):
        self.Checksum = self.calculateChecksum()

    def verifyChecksum(self):
        return self.Checksum == self.calculateChecksum()

    def __lt__(self, other):
        return self.SequenceNumber < other.SequenceNumber

    @classmethod
    def Create_SYN(cls):
        seq_number = random.randint(0, 2**16)
        packet = cls(Type=cls.SYN, SequenceNumber=seq_number, Checksum=0)
        packet.updateChecksum()
        return packet

    @classmethod
    def Create_SYN_ACK(cls, client_seq_num):
        seq_number = random.randint(0, 2**16)
        packet = cls(Type=cls.SYN_ACK, SequenceNumber=seq_number,
                     Checksum=0, Acknowledgement=client_seq_num + 1)
        packet.updateChecksum()
        return packet

    @classmethod
    def Create_handshake_ACK(cls, server_seq_num, client_seq_num):
        packet = cls(Type=cls.ACK, SequenceNumber=client_seq_num +
                     1, Checksum=0, Acknowledgement=server_seq_num + 1)
        packet.updateChecksum()
        return packet

    @classmethod
    def Create_packet_ACK(cls, expected_seq_number):
        packet = cls(Type=cls.ACK, Checksum=0,
                     Acknowledgement=expected_seq_number)
        packet.updateChecksum()
        return packet

    @classmethod
    def Create_RIP(cls, expected_seq_number):
        packet = cls(
            Type=cls.RIP, SequenceNumber=expected_seq_number, Checksum=0)
        packet.updateChecksum()
        return packet

    @classmethod
    def Create_RIP_ACK(cls, expected_seq_num, sender_seq_num):
        packet = cls(Type=cls.RIP_ACK, SequenceNumber=expected_seq_num,
                     Checksum=0, Acknowledgement=sender_seq_num + 1)
        packet.updateChecksum()
        return packet

    @classmethod
    def Create_DATA(cls, seq_number, data, size_for_previous_data):
        packet = cls(Type=cls.DATA, SequenceNumber=seq_number +
                     size_for_previous_data, Checksum=0, Data=data)
        packet.updateChecksum()
        return packet





MOBILE_CODE_PACKAGE = "playground.org.mobilecode."


class MobileCodePacket(PacketType):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "MobileCodePacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = []


class MobileCodeServiceDiscovery(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "MobileCodeServiceDiscovery"
    DEFINITION_VERSION = "1.0"
    FIELDS = []


class MobileCodeServiceDiscoveryResponse(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "MobileCodeServiceDiscoveryResponse"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Address", STRING),
        ("Port", UINT16),
        ("Traits", LIST(STRING))
    ]


class OpenSession(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "OpenSession"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
    ]


class OpenSessionResponse(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "OpenSessionResponse"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("WalletId", STRING),
        ("AuthId", STRING),
        ("EngineId", STRING),
        ("NegotiationAttributes", LIST(STRING))
    ]


class RunMobileCode(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "RunMobileCode"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("Code", STRING)
    ]


class GetMobileCodeStatus(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "GetMobileCodeStatus"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64)
    ]


class GetMobileCodeStatusResponse(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "GetMobileCodeStatusResponse"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("Complete", BOOL),
        ("Runtime", UINT32)
    ]


class GetMobileCodeResult(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "GetMobileCodeResult"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64)
    ]


class GetMobileCodeResultResponse(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "GetMobileCodeResultResponse"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("Result", BUFFER),
        ("Charges", UINT32)
    ]


class Payment(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "SubmitPayment"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("PaymentData", BUFFER)
    ]


class PaymentResponse(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "SubmitPaymentResult"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("Authorization", BUFFER)
    ]


class MobileCodeFailure(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "MobileCodeFailure"
    DEFINITION_VERSION = "1.0"
    FIELDS = []


class GeneralFailure(MobileCodeFailure):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "GeneralFailure"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("ErrorMessage", STRING),
        ("Closed", BOOL)
    ]


class AuthFailure(MobileCodeFailure):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "AuthFailure"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("ErrorMessage", STRING),
        ("Closed", BOOL)
    ]


class WalletFailure(MobileCodeFailure):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "WalletFailure"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("ErrorMessage", STRING),
        ("Closed", BOOL)
    ]


class EngineFailure(MobileCodeFailure):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE + "EngineFailure"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("ErrorMessage", STRING),
        ("Closed", BOOL)
    ]


class demuxer:
    def connectionMade():
        pass

    def demux(src, srcPort, dst, dstPort, demuxData):
       # dmux data is ***RAW*** data on Playground.
        print("*******************   RAW   Packet   **********************")
        print("src is       :", src)
        print("srcPort is   :", srcPort)
        print("dst is       :", dst)
        print("dstPort is   :", dstPort)
        # print("demuxData is :", demuxData)

        deserializer0 = PEEPPacket.Deserializer()
        deserializer0.update(demuxData)
        for pkt in deserializer0.nextPackets():
            if isinstance(pkt, PEEPPacket):
                print("^^^^^^^^^^^^^^^^^^^   PEEP  Packet   ^^^^^^^^^^^^^^^^^^^^^^^")
                print("SequenceNumber is : ", pkt.SequenceNumber)
                print("Type is           : ", pkt.Type)
                print("Checksum is       : ", pkt.Checksum)
                print("Ack is            : ", pkt.Acknowledgement)
                print("Data is           : ", pkt.Data)
                print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")

        deserializer1 = MobileCodePacket.Deserializer()
        deserializer1.update(demuxData)

        for pkt in deserializer1.nextPackets():
            if isinstance(pkt, Payment):
                print("^^^^^^^^^^^^^^   Mobo Payment  Packet   ^^^^^^^^^^^^^^^^^^^^")
                print("Cookie is       : ", pkt.Cookie)
                print("PaymentData is  : ", pkt.Type)
                print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
            if isinstance(pkt, GetMobileCodeStatus):
                print("^^^^^^^^^^^^^   GetMobileCodeStatus  Packet   ^^^^^^^^^^^^^^")
                print("Cookie is       : ", pkt.Cookie)
                print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
            if isinstance(pkt, GetMobileCodeStatusResponse):
                print("^^^^^^^^^^^^^   GetMobileCodeStatus  Packet   ^^^^^^^^^^^^^^")
                print("Cookie is       : ", pkt.Cookie)
                print("Complete is     : ", pkt.Complete)
                print("Runtime is      : ", pkt.Runtime)
                print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")

        print("************************************************************")


eavesdrop = playground.network.protocols.switching.PlaygroundSwitchTxProtocol(demuxer, "20174.*.*.*")
loop = asyncio.get_event_loop()
coro = loop.create_connection(lambda: eavesdrop,"192.168.200.240",9090)
loop.run_until_complete(coro)
loop.run_forever()



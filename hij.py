import asyncio, playground
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT16, UINT32, UINT64, LIST, BUFFER, STRING, BOOL
#from playground.network.packet.fieldtypes.attributes import Optional
#from playground.common import CustomConstant as Constant

MOBILE_CODE_PACKAGE = "playground.org.mobilecode."

class MobileCodePacket(PacketType):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"MobileCodePacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = []

class MobileCodeServiceDiscovery(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"MobileCodeServiceDiscovery"
    DEFINITION_VERSION = "1.0"
    FIELDS = []

class MobileCodeServiceDiscoveryResponse(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"MobileCodeServiceDiscoveryResponse"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Address", STRING),
        ("Port", UINT16),
        ("Traits", LIST(STRING))
        ]

class OpenSession(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"OpenSession"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ]

class OpenSessionResponse(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"OpenSessionResponse"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("WalletId", STRING),
        ("AuthId", STRING),
        ("EngineId", STRING),
        ("NegotiationAttributes", LIST(STRING))
        ]

class RunMobileCode(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"RunMobileCode"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("Code", STRING)
        ]

class GetMobileCodeStatus(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"GetMobileCodeStatus"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64)
        ]

class GetMobileCodeStatusResponse(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"GetMobileCodeStatusResponse"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("Complete", BOOL),
        ("Runtime", UINT32)
        ]

class GetMobileCodeResult(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"GetMobileCodeResult"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64)
        ]

class GetMobileCodeResultResponse(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"GetMobileCodeResultResponse"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("Result", BUFFER),
        ("Charges", UINT32)
        ]

class Payment(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"SubmitPayment"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("PaymentData", BUFFER)
        ]

class PaymentResponse(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"SubmitPaymentResult"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("Authorization", BUFFER)
        ]

class MobileCodeFailure(MobileCodePacket):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"MobileCodeFailure"
    DEFINITION_VERSION = "1.0"
    FIELDS = []

class GeneralFailure(MobileCodeFailure):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"GeneralFailure"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("ErrorMessage", STRING),
        ("Closed", BOOL)
        ]

class AuthFailure(MobileCodeFailure):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"AuthFailure"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("ErrorMessage", STRING),
        ("Closed", BOOL)
        ]

class WalletFailure(MobileCodeFailure):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"WalletFailure"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("ErrorMessage", STRING),
        ("Closed", BOOL)
        ]

class EngineFailure(MobileCodeFailure):
    DEFINITION_IDENTIFIER = MOBILE_CODE_PACKAGE+"EngineFailure"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Cookie", UINT64),
        ("ErrorMessage", STRING),
        ("Closed", BOOL)
        ]

class ColorClientPro(asyncio.Protocol):

    def __init__(self, cookie):
        self.cookie = cookie

    def sendfirst(self):
        response = GetMobileCodeStatusResponse(Cookie=self.cookie, Complete=True, Runtime=3)
        for i in range(10):
            self.transport.write(response.__serialize__())
        f.close()

    def connection_made(self, transport):
        self.transport = transport
        self.sendfirst()


class demuxer:


    def connectionMade():
        pass

    def demux(src, srcPort, dst, dstPort, demuxData):
        print("----")
        deserializer1 = MobileCodePacket.Deserializer()
        deserializer1.update(demuxData)

        for pkt in deserializer1.nextPackets():
            if isinstance(pkt, GetMobileCodeStatus):
                print("+++++++++++++++++++++++++")
                if dstPort == "20174.1.1337.4":
                    iloop = asyncio.get_event_loop()
                    coro = playground.getConnector().create_playground_connection(lambda: ColorClientPro(pkt.Cookie), src, srcPort)
                    iloop.run_until_complete(coro)
                    iloop.run_forever()


eavesdrop = playground.network.protocols.switching.PlaygroundSwitchTxProtocol(demuxer, "20174.*.*.*")
loop = asyncio.get_event_loop()
coro = loop.create_connection(lambda: eavesdrop,"192.168.200.240",9090)
loop.run_until_complete(coro)
loop.run_forever()




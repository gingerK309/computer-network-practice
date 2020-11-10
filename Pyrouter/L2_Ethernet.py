from Dictionary import *
import  struct

class L2_Ethernet:
    def __init__(self,name,src):
        self.name = name
        self.underLayer = None
        self.upperLayer = None

        self._dst = None
        self._src = src
        self._type = None
        self._data = None

    def connectLayers(self,underLayer, upperLayers):
        #이더넷 상위 레이어 IP, ARP임, 배열 형태로 전달받음
        self.underLayer = underLayer
        self.upperLayer = upperLayers

    def set_dst(self,ARP_MAC_address): #이더넷 목적지 주소 설정
        self._dst = ARP_MAC_address #ARP한테 전달받은 이더넷 주소

    def receive(self,ppayload):
        #이더넷 헤더 분석
        self.extractHeader(ppayload)
        print('받은 패킷: ',ppayload)
        #이더넷 헤더 목적지가 자기 자신의 MAC이면 프레임 타입을 비교함
        if self._pdst == ETH_ADDR_BROADCAST or self._src ==self._pdst:
            if self._src == self._psrc: #패킷이 자기자신이면 분석하지 않음
                return
            if self._ptype == ETHERNET_TYPE_IP:
                self.upperLayers[0].receive(self._pdata) #프레임 타입이 0x0800 이면 IP로 전달

            if self._ptype == ETHERNET_TYPE_ARP:
                self.upperLayers[1].receive(self._pdata) #프레임 타입이 0x0806 이면 ARP로 전달

    def send(self,data,type, opt =None):
        #IP나 ARP한테 받은 패킷을 이더넷 프레임을 씌워 NI 전달
        if type == ETHERNET_TYPE_IP: #상위 계층에서 받은 프레임 타입이 IP면
            self._type = ETHERNET_TYPE_IP
        if type == ETHERNET_TYPE_ARP: #상위 계층에서 받은 프레임 타입이 ARP면
            self._type = ETHERNET_TYPE_ARP

        self.underLayer.send(self.generatePayload(data))
        #NILayer의 send함수 호출한 다음 생성한 이더넷 프레임 전달

    def extractHeader(self,raw): #NI한테 받은 패킷 이더넷 프레임에 맞춰서 분석
        self._pdst = raw[:6]
        self._psrc = raw[6:12]
        self._ptype=raw[12:14]
        self._pdata = raw[14:]
        self._pheader = raw[:14]

    def generatePayload(self,data): #이더넷 프레임 생성
        #todo 향후 수정
        self._data = data
        return self._dst + self._src + self._type +self._data



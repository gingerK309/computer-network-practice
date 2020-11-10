from Dictionary import *
import  struct
from FowardingTable import *

class L3_IP:
    def __init__(self,name):
        self.name= name
        self.underLayers =None
        self.upperLayer=None
        self.arpLayers =None

        self._verlen = None
        self._service = None
        self._total =None # IP 헤더 길이 + 데이터 길이
        self._id = None
        self._flag_and_offset = None
        self._ttl = None
        self._type = None
        self._check_sum = None
        self._src =None
        self._dst =None

        self.fowardingtable = None

    def connectLayers(self,underLayers, upperLayer, arpLayers):
        #IP의 경우 하위 레이어 및 arp 레이어를 인터페이스 개수 만큼 보유해야 하므로 배열 형태로 전달 받음
        self.underLayers = underLayers
        self.upperLayer= upperLayer
        self.arpLayers = arpLayers

    def connectTable(self,fowardingtable):
        self.fowardingtable = fowardingtable

    def receive(self,ppayload):
        #IP 헤더 분석
        self.extractHeader(ppayload)
        index = self.fowardingtable.search(self._pdst)
        if index != None: #index 찾음
            self.send(index)

    def send(self,index): #라우팅 과정 수행 결과에 따른 IP 패킷 생성 후 이더넷 레이어로 전달
        print('튜플: ',self.fowardingtable.get_tuple(index))
        #라우팅 테이븙 탐색
        address,netmask,gateway,flag,ifnum,metric = self.fowardingtable.get_tuple(index)
        if flag == FLAG_UH:
            #ARP 캐시 테이블 확인을 위해 추출한 주소를 ARP에 전달
            result =self.arpLayers[ifnum].checkARPCacheTable(self._pdst)
        elif flag == FLAG_UG:
            result = self.arpLayers[ifnum].checkARPCacheTable(gateway)
        if result == True:
            #이더넷 레이어로 생성된 IP 패킷 전달
            self.underLayers[ifnum].send(self.generatePayload(),ETHERNET_TYPE_IP)

    def extractHeader(self,raw):
        self._pverlen =raw[:1]
        self._pservice = raw[1:2]
        self._ptotal = raw[2:4]
        self._pid = raw[4:6]
        self._pflag_and_offset = raw[6:8]
        self._pttl = raw[8:9]
        self._ptype = raw[9:10]
        self._pcheck_sum = raw[10:12]
        self._psrc = raw[12:16]
        self._pdst= raw[16:20]
        self._data = raw[20:]
        self._pheader =raw[:20]

    def generatePayload(self):
        return  self._pverlen + self._pservice + self._ptotal + self._pid
        + self._pflag_and_offset + self._pttl + self._ptype + self._pcheck_sum
        +self._psrc + self._pdst + self._data

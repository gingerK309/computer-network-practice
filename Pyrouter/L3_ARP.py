from Dictionary import *
import struct
from ARPCacheTable import *

class L3_ARP:
    def __init__(self,name,my_mac,my_ip):
        self.name = name
        self.underLayer = None
        self.upperLayer = None

        self._hard_type = b'\x00\x01'
        self._proto_type = b'\x08\x00'
        self._hard_len = b'\x06'
        self._proto_len = b'\x04'
        self._opcode = None
        self._sender_mac = my_mac
        self._sender_ip = my_ip
        self._target_mac = None
        self._target_ip = None
        self.arptable = None

    def connectTable(self,arptable):
        self.arptable = arptable

    def connectLayers(self,underLayer,upperLayer):
        self.underLayer = underLayer
        self.upperLayer = upperLayer
        
    def receive(self,ppayload): #이더넷으로 패킷 수신
        print('[Layer '+self.name+' ] Called receive()')
        
        #ARP 헤더 분석
        self.extractHeader(ppayload)

        proxy_i = self.arptable.proxysearch(self._ptarget_ip)
        if proxy_i != None:
            self.sendPARPReply(self.artable.proxy_get_ip(proxy_i))

        if self._ptarget_ip != self._sender_ip: #수신 패킷 target_ip가 sender가 아니면 무시
            return

        if self._psender_ip == self._sender_ip:
            return #수신된 패킷 sender_ip가 자기자신이면 무시

        if self._popcode == ARP_OPCODE_REQUEST: # 수신된 ARP 메시지 오프 코드확인
            #오프 코드가 1이면 ARP request
            index = self.arptable.search(self._psender_ip) #sender에 대한 정보 등록
            if index == None:
                self.arptable.insert(self._psender_ip,self._psender_mac)
            else:
                self.arptable.update(index,self._psender_mac)

            if self._psender_ip != self._ptarget_ip:#Gratuitous ARP가 아니면
                self.sendARPReply()

        if self._popcode == ARP_OPCODE_REPLY: #opcode가 2이면 ARP reply
            index = self.arptable.search(self._psender_ip)
            #ARP 메시지 sender ip 주소 및 sender mac 주소를 이용해 ARP 캐시 테이블에 등록
            if index == None:
                self.arptable.insert(self._psender_ip, self._psender_mac)
            else:
                self.arptable.update(index,self._psender_mac)
    
    def send(self,data): #이더넷으로 패킷 전달
        print('[Layer '+self.name+'] Called send()')
        self.underLayer.send(data, ETHERNET_TYPE_ARP)

    def extractHeader(self, raw):
        self._phard_type =raw[:2]
        self._pproto_type = raw[2:4]
        self._phard_len = raw[4:5]
        self._pproto_len = raw[5:6]
        self._popcode = raw[6:8]
        self._psender_mac = raw[8:14]
        self._psender_ip = raw[14:18]
        self._ptarget_mac = raw[18:24]
        self._ptarget_ip = raw[24:28]
        self._pheader = raw[:28]

    #todo ARP 캐시테이블에서 정보 찾기

    def checkARPCacheTable(self,ipdst):
        print('TODO: ARB 캐시 테이블 탐색',ipdst)
        index =self.arptable.search(ipdst) #ipdst에 매핑되는 이더넷 주소 찾기
        if index != None: #찾았으면 이더넷 레이어의 dst 주소로 설정
            print('[Layer '+self.name+'] ARP cache entry 찾기 성공')
            eth_dst = self.arptable.get_mac(index) #하위 레이어 dst를 ipdst에 해당하는 MAC 주소로 설정
            self.underLayer.set_dst(eth_dst)
            return True
        else:
            print('[Layer '+self.name+'] ARP cache entry 찾기 실패')
            self.sendARPRequest(ipdst)
            return False

    def sendARPRequest(self,ipdst):
        print('[Layer ' + self.name + '] Called sendARPRequest()')
        #ARP 리퀘스트 메시지 생성
        self._hard_type = b'\x00\x01'
        self._proto_type = b'\x08\x00'
        self._hard_len = b'\x06'
        self._proto_len = b'\x04'
        self._opcode = ARP_OPCODE_REQUEST
        self._target_mac = b'\x00\x00\x00\x00\x00\x00'
        self._target_ip = ipdst

        self.underLayer.set_dst(b'\xff\xff\xff\xff\xff\xff')
        print(self.generatePayload()) #생성된 ARP 리퀘스트 메시지 확인
        self.send(self.generatePayload()) #send 함수 호출 후 생성된 메시지 전달

    def sendARPReply(self):
        print('[Layer ' + self.name + '] Called sendARPReply()')
        #ARP 응답 메시지 작성
        self._hard_type = self._phard_type
        self._proto_type = self._pproto_type
        self._hard_len = self._phard_len
        self._proto_len = self._pproto_len
        self._opcode = ARP_OPCODE_REPLY
        self._target_mac = self._psender_mac
        self._target_ip = self._psender_ip
        
        self.underLayer.set_dst(self._psender_mac)
        #send 함수 호출 수 생성된 메시지 전달
        self.send(self.generatePayload())

    def generatePayload(self): #ARP 메시지 생성
        return self._hard_type + self._proto_type + self._hard_len + self._proto_len
        +self._opcode+ self._sender_mac+self._sender_ip+self._target_mac+self._target_ip
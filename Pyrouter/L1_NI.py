from scapy.sendrecv import sendp
from Dictionary import *
import  struct
import pcap
import threading

class L1_NI:
    def __init__(self,name):
        self.name = name
        self.underLayer = None
        self.upperLayer = None
        self.device = None
        self.ifnum = -1

    def connectLayers(self,underLayer,upperLayer): #레이어 상,하위 정보 설정
        self.underLayer = underLayer
        self.upperLayer = upperLayer

    def getAdapterList(self):
        print('[Layer'+self.name+'] Called setAdapter()')
        print('TODO: Sniffer를 이용한 네트워크 어댑터 설정')
        self.devices = pcap.findalldevs() #네트워크 어댑터 리스트 불러오기
        i=0
        buf = ''
        for dev in self.devices: # 어댑터로 하나씩 불러와서 출력
             buf = buf + (str(i)+') '+dev+', ')
             i=i+1
        print(buf)

    def setAdapter(self,ifnum):
        self.ifnum = ifnum
        print('Selected '+ifnum+'th device: '+self.devices[int(self.ifnum)])

    def execute(self):
        print(threading.currentThread().getName(),self.name)
        packets = pcap.pcap(name= self.devices[int(self.ifnum)],promisc=True,immediate=True,timeout_ms=50)

        for ts,ppayload in packets:
            self.receive(ppayload)

    def startAdapter(self):
        my_thread = threading.Thread(target=self.execute(),args=())
        my_thread.start()

    def receive(self,ppayload):
        self.upperLayer.receive(ppayload)

    def send(self,data): # IP나 ARP한테 받은 패킷을 이더넷 프레임 씌워 NI 전달
        sendp(data,iface = self.devices[int(self.ifnum)])
        pass
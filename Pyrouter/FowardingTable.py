import struct

class FowardingTable:
    def __init__(self, name):
        self.name = name
        self.fowardingTable = [] # 목적지, 넷마스크, 게이트웨이, 플래그, 인터페이스, 메트릭

    def getTable(self):
        return  self.fowardingTable

    def search(self,dst_ip): # 포워딩 테이블 검색
        print('탐색 시작: ',dst_ip)
        for i in range(len(self.fowardingTable)):
            address = self.fowardingTable[i][0]
            netmask = self.fowardingTable[i][1]

            print('어드레스: ', address,'넷마스크: ',netmask)
            if self.byte_and_operator(dst_ip,netmask) == address: 
                # 수신 패킷 목적지에 맞는 네트워크 탐색
                print('일치 튜플: ',i)
                return  i
        #주소 못찾음
        print('탐색 실패')
        return None

    def byte_and_operator(self,address,netmask):
        (addr0,addr1,addr2,addr3)= struct.unpack('!4B',address)
        (net0,net1,net2,net3) = struct.unpack('!4B',netmask)

        ret_val = struct.pack('!4B',addr0 & net0, addr1 & net1, addr2 & net2, addr3 & net3)
        print('리턴 값: ',ret_val)
        return  ret_val
    
    def insert(self,dst_ip,netmask,gateway_ip,flag,interface,metric): #라우팅 테이블 요소 입력
        print('라우팅 테이블 삽입')
        self.fowardingTable.append([dst_ip,netmask,gateway_ip,flag,interface,metric])
        print(self.fowardingTable)
        
    def update(self,i,netmask,gateway_ip,flag,interface,metric):
        # 인덱스 입력받아 i번째 항목 수정
        print('라우팅 테이블 업데이트')
        self.fowardingTable[i][1]=netmask
        self.fowardingTable[i][2]= gateway_ip
        self.fowardingTable[i][3] = flag
        self.fowardingTable[i][4] = interface
        self.fowardingTable[i][5] = metric

    def delete(self):
        pass

    def header(self,packet): #todo 몇 바이튼지 모름
        self._pdst_ip = packet[:4]
        self._pnetmask=packet[4:8]
        self._pgateway_ip =packet[8:12]
        self._pflag = packet[12:15]

    def get_tuple(self,i):
        if i == None:
            return None
        return self.fowardingTable[i][0],self.fowardingTable[i][1],self.fowardingTable[i][2],self.fowardingTable[i][3],\
               self.fowardingTable[i][4],self.fowardingTable[i][5]

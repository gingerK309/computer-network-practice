class ARPCacheTable:
    def __init__(self,name):
        self.name = name
        self.arpcachetable = [] #ip,eth 순

    def getTable(self):
        return self.arpcachetable

    def insert(self,arp_ip, arp_eth):
        print('ARP_INSERT')
        self.arpcachetable.append([arp_ip,arp_eth])

    def update(self,i,arp_eth): # 인덱스 입력으로 i번쨰 mac 주소 지정
        print('ARP_UPDATE')
        self.arpcachetable[i][1] = arp_eth
        
    def delete(self):
        pass
    
    def search(self,arp_ip): #찾는 ip 가 있으면 주소 리턴
        for i in range(len(self.arpcachetable)):
            if self.arpcachetable[i][0] == arp_ip:
                return i
            return None

    def get_ip(self,i):
        return self.arpcachetable[i][0]

    def get_mac(self,i):
        return  self.arpcachetable[i][1]
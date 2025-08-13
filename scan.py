import mysql.connector
from scapy.all import ARP, Ether, srp
import socket
import time
from datetime import datetime

# --- 資料庫配置 ---
DB_CONFIG = {
    'host': 'localhost',
    'user': 'your_user', ### peter
    'password': 'your_password',  ### x-------
    'database': 'network_scan'
}

# --- 掃描函數 ---
def scan_network(network_range):
    """
    使用 ARP 封包掃描指定網段，返回 IP 和 MAC 位址。
    """
    # 建立 ARP 請求封包
    arp_request = ARP(pdst=network_range)
    # 建立乙太網路廣播封包
    broadcast_ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # 結合封包
    packet = broadcast_ether / arp_request

    # 發送並接收回應，設定超時時間為 1 秒
    answered, unanswered = srp(packet, timeout=1, verbose=0)
    
    devices = []
    for sent, received in answered:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'hostname': get_hostname(received.psrc)
        })
    return devices

def get_hostname(ip_address):
    """
    嘗試從 IP 位址獲取主機名稱。
    """
    try:
        # 使用 socket.gethostbyaddr 進行反向 DNS 查詢
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        # 如果無法解析，返回 None
        return None

# --- 資料庫操作函數 ---
def connect_db():
    """
    連接到 MySQL 資料庫。
    """
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None

def update_database(devices):
    """
    將掃描到的設備資訊更新到資料庫中。
    """
    db_conn = connect_db()
    if not db_conn:
        return

    cursor = db_conn.cursor()
    
    current_time = datetime.now()
    unusual_time = False
    # 判斷是否為非正常時間 (21:00-06:00)
    if current_time.hour >= 21 or current_time.hour < 6:
        unusual_time = True

    for device in devices:
        ip = device['ip']
        mac = device['mac']
        hostname = device['hostname']

        # 檢查 IP 是否已存在
        cursor.execute("SELECT * FROM ip_devices WHERE ip_address = %s", (ip,))
        result = cursor.fetchone()

        if result:
            # 如果存在，更新 last_seen 和 unusual_time_count
            update_sql = """
            UPDATE ip_devices 
            SET mac_address = %s, hostname = %s, last_seen = %s, 
            unusual_time_count = unusual_time_count + %s
            WHERE ip_address = %s
            """
            unusual_increment = 1 if unusual_time else 0
            cursor.execute(update_sql, (mac, hostname, current_time, unusual_increment, ip))
        else:
            # 如果不存在，新增一筆記錄
            insert_sql = """
            INSERT INTO ip_devices 
            (ip_address, mac_address, hostname, first_seen, last_seen, unusual_time_count) 
            VALUES (%s, %s, %s, %s, %s, %s)
            """
            unusual_increment = 1 if unusual_time else 0
            cursor.execute(insert_sql, (ip, mac, hostname, current_time, current_time, unusual_increment))

    # 提交變更並關閉連接
    db_conn.commit()
    cursor.close()
    db_conn.close()
    print(f"Successfully updated {len(devices)} devices in the database.")


# --- 主程式 ---
if __name__ == "__main__":
    # 定義要掃描的 IP 網段範圍
    start_subnet = 0
    end_subnet = 50
    
    all_devices = []

    for i in range(start_subnet, end_subnet + 1):
        # 構造每個子網路的 CIDR 表示法
        network_range = f"172.20.{i}.0/24"
        
        print(f"[{datetime.now()}] Scanning network range: {network_range}...")
        
        # 執行網路掃描
        devices = scan_network(network_range)
        all_devices.extend(devices)

    if all_devices:
        # 更新資料庫
        update_database(all_devices)
    else:
        print("No devices found in the network.")
    
    print("Scan finished.")

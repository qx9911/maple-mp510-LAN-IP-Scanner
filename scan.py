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

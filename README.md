# maple-mp510-LAN-IP-Scanner

#host: maple MP510, 172.20.50.2
#app : /home/peter/0813-lan-monitor
# sql
CREATE DATABASE IF NOT EXISTS network_scan;

USE network_scan;

CREATE TABLE IF NOT EXISTS ip_devices (
    ip_address VARCHAR(15) NOT NULL PRIMARY KEY,
    mac_address VARCHAR(17),
    hostname VARCHAR(255),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    unusual_time_count INT DEFAULT 0
);

# app.py


# maple mp510's enviroment
sudo apt update
sudo apt install bash-completion curl wget nano
sudo apt install net-tools
sudo apt install build-essential
sudo apt install python3-pip

# mp510 must use sudo
sudo reboot
sudo poweroff
sudo shutdown now

# menv
sudo apt update
sudo apt install python3-venv
python3 -m venv myenv
source myenv/bin/activate  
pip install scapy mysql-connector-python python-nmap  #deactivate to exit menv

. myenv/bin/activate
./myenv/bin/pip install scapy mysql-connector-python python-nmap
/home/peter/myenv/bin/python -m pip install scapy mysql-connector-python python-nmap
sudo /home/peter/works/0813-lan-monitor/myenv/bin/python3 scan.py

#crontab
*/5 * * * * /home/peter/works/0813-lan-monitor/myenv/bin/python3 /home/peter/works/0813-lan-monitor/scan.py






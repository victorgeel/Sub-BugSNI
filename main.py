import ipaddress, requests
from multiprocessing import Process
import time, random

ip_ranges = [line.strip() for line in open('ip.txt', 'r').readlines()] #IP ranges

def range_test(network, ping):
    for ip in network:
        try:
            start_time = time.time()
            result = requests.get(f"https://{ip}/__down", timeout=(10,10))
            end_time = time.time()
            ping_time = round((end_time - start_time) * 1000, 2)
            if int(ping_time) <= ping:
                print(f"Clean IP : {ip} (Ping: {ping_time} ms)")
        except Exception as e:
            if "CERTIFICATE_VERIFY_FAILED" in str(e):
                end_time = time.time()
                ping_time = round((end_time - start_time) * 1000, 2)
                if int(ping_time) <= ping:
                    print(f"Clean IP : {ip} (Ping: {ping_time} ms)")

if __name__ == '__main__':
    ping = int(input('Enter the maximum delay recommend 3000(Ping) ms <= 10000 : '))
    number_of_ranges = int(input('Enter a number of IP ranges you want scan randomly (Enter a lower number for weak CPU) : '))
    ip_ranges = random.sample(ip_ranges, number_of_ranges)
    for ip_range in ip_ranges:
        print(ip_range, 'Started !')
        network = ipaddress.ip_network(ip_range)
        Process(target=range_test, args=(network, ping)).start()

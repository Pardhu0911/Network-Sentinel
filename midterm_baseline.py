from scapy.all import sniff, IP, ICMP, TCP, UDP
import time

# Dictionary to store packet counts: { "IP_Address": count }
packet_counts = {}
# Set the limit: 100 packets from the same IP within the check interval
THRESHOLD = 100 
last_check_time = time.time()

def detect_attack(packet):
    global last_check_time
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        
        # Increase count for this specific IP
        packet_counts[src_ip] = packet_counts.get(src_ip, 0) + 1
        
        # Every 1 second, check if any IP exceeded the threshold
        if time.time() - last_check_time > 1:
            for ip, count in packet_counts.items():
                if count > THRESHOLD:
                    # Classify the attack type
                    attack_type = "Unknown Flood"
                    if packet.haslayer(ICMP): attack_type = "ICMP Flood"
                    elif packet.haslayer(TCP): attack_type = "TCP SYN Flood"
                    elif packet.haslayer(UDP): attack_type = "UDP Flood"
                    
                    print(f"!!! ATTACK DETECTED !!!")
                    print(f"Type: {attack_type}")
                    print("Source crossed the observation threshold.")
                    print(f"Packet Count: {count} pkts/sec\n")
            
            # Reset counts for the next second
            packet_counts.clear()
            last_check_time = time.time()

if __name__ == "__main__":
    print("Passive threshold monitor. Press Ctrl+C to stop.")
    try:
        sniff(prn=detect_attack, store=False)
    except KeyboardInterrupt:
        pass

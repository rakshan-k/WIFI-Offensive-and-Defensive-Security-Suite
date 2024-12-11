from scapy.all import *
import time

def create_fake_ap(iface, ssid, duration):
    sender_mac = RandMAC()

    # 802.11 frame
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)

    # Beacon layer
    beacon = Dot11Beacon()

    # Putting SSID in the frame
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))

    # Stack all the layers and add a RadioTap
    frame = RadioTap()/dot11/beacon/essid

    # Start time
    start_time = time.time()

    print(f"[+] Sending beacon frames for SSID '{ssid}' on interface '{iface}' for {duration} seconds...")

    # Send the frame in layer 2 every 100 milliseconds
    try:
        while time.time() - start_time < duration:
            sendp(frame, inter=0.1, iface=iface, verbose=1, count=1)
    except KeyboardInterrupt:
        print("\n[!] Sending interrupted by user.")
    finally:
        print("[+] Done sending beacon frames.")


create_fake_ap("wlan0mon", "test", 10)


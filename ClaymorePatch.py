# Credits to gkovacs for open sourcing his mining fee remover. He's a babe. 
# https://github.com/gkovacs
# Drake Auton @ FOX Mining Hardware


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import nfqueue
from scapy.all import *
import os
import re

from os import path

os.system('iptables -A OUTPUT -p tcp --dport 9999 -j NFQUEUE --queue-num 0')

try: 
	my_eth_address = raw_input("Ethereum Address to Redirect Fee:")
	print("Okay, using address " + my_eth_address)
except IndexError:
	print(" [!] Please enter a valid Ethereum address.")
	time.sleep(2)
	sys.exit(1)

addresses_to_redirect = [re.compile(re.escape(x.lower()), re.IGNORECASE) for x in [
  '0x3509F7bd9557F8a9b793759b3E3bfA2Cd505ae31',
  '0xc6F31A79526c641de4E432CB22a88BB577A67eaC',
  '0x713ad5bd4eedc0de22fbd6a4287fe4111d81439a',
  '0xb4675bc23d68c70a9eb504a7f3baebee85e382e7',
  '0x1a31d854af240c324435df0a6d2db6ee6dc48bde',
  '0x9f04b72ab29408f1f47473f2635e3a828bb8f69d',
  '0xea83425486bad0818919b7b718247739f6840236',
  '0xc1c427cd8e6b7ee3b5f30c2e1d3f3c5536ec16f5',
  '0xb9cf2da90bdff1bc014720cc84f5ab99d7974eba',
  '0xaf9b0e1a243d18f073885f73dbf8a8a34800d444',
  '0xe19ffb70e148a76d26698036a9ffd22057967d1b',
  '0x7fb21ac4cd75d9de3e1c5d11d87bb904c01880fc',
  '0xde088812a9c5005b0dc8447b37193c9e8b67a1ff',
  '0x34faaa028162c4d4e92db6abfa236a8e90ff2fc3',
  '0x368fc687159a3ad3e7348f9a9401fc24143e3116',
  '0xaf9b0e1a243d18f073885f73dbf8a8a34800d444',
  '0xc1c427cd8e6b7ee3b5f30c2e1d3f3c5536ec16f5',
  '0x9f04b72ab29408f1f47473f2635e3a828bb8f69d',
  '0xea83425486bad0818919b7b718247739f6840236',
  '0x1a31d854af240c324435df0a6d2db6ee6dc48bde',
  '0xb4675bc23d68c70a9eb504a7f3baebee85e382e7',
  '0x713ad5bd4eedc0de22fbd6a4287fe4111d81439a',
  '0x39c6e46623e7a57cf1daac1cc2ba56f26a8d32fd'
]]

logfile = open('remove_mining_fees_log.txt', 'w', 0)

def callback(arg1, payload):
  data = payload.get_data()
  pkt = IP(data)

  payload_before = len(pkt[TCP].payload)

  payload_text = str(pkt[TCP].payload)
  for address_to_redirect in addresses_to_redirect:
    payload_text = address_to_redirect.sub(my_eth_address, payload_text)
  pkt[TCP].payload = payload_text

  payload_after = len(payload_text)

  payload_dif = payload_after - payload_before

  pkt[IP].len = pkt[IP].len + payload_dif

  pkt[IP].ttl = 40

  del pkt[IP].chksum
  del pkt[TCP].chksum
  payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
  logfile.write(payload_text)
  logfile.write('\n')
  logfile.flush()
def main():
  q = nfqueue.queue()
  q.open()
  q.bind(socket.AF_INET)
  q.set_callback(callback)
  q.create_queue(0)
  try:
    q.try_run()
  except KeyboardInterrupt:
    q.unbind(socket.AF_INET)
    q.close()
    if path.exists('./restart_iptables'):
      os.system('./restart_iptables')

main()
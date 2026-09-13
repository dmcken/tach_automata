import json
import os
import sys

import tach_automata

pw = os.environ['TACH_PW']
user = os.environ['TACH_USER']

ip = sys.argv[1]
dev = tach_automata.TachyonDevice(ip)
dev.login([pw], username=user)
data = dev.get_stats('network,wireless,ethernet')
print(json.dumps(data, indent=2))

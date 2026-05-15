import os, socket, time

system_uptime  = time.monotonic()
hours = int(system_uptime // 3600)
minutes = int(system_uptime % 3600 // 60)
seconds = int(system_uptime % 60)

#print('System has been up for ' + hours, minutes, seconds)

print(system_uptime)
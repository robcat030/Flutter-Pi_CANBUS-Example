#!/usr/bin/env python3

"""
This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.
This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

from csv import Sniffer
import sys
import os
from time import sleep, time
from math import ceil
from io import BytesIO

import can
from subprocess import Popen, PIPE

from ford.vbf import Vbf
from ford.uds import keygen, fixedbytes, Ecu
from flask import Flask,jsonify

app = Flask(__name__)

@app.route('/', methods=['GET'])

def index():
    # returning key-value pair in json format
	rpm = sniffloop1()
	if rpm:
		return jsonify({'test': rpm})

def tccheck(can_interface):	
	cmd = "tc qdisc show | grep {} | cut -f2 -d' '".format(can_interface)

	with Popen(cmd, shell=True, stdout=PIPE, preexec_fn=os.setsid) as process:
		output = process.communicate()[0]

	if output:
		if 'fifo' in output.decode("utf-8"):
			return True

	return False

def sniffloop1():
	rpm = PID_Requester.ecu.getHWPartNo()
	if rpm:
		debug("\n[?] HWPartNo: {}".format(rpm))
		return rpm
	else:
		false = "false"
		return false

class FordCANSniffer:
	def __init__(self, can_interface="can0", ecuid="0x7E0"):
		self.ecuid = ecuid

		self.ecu = Ecu(can_interface=can_interface, ecuid=self.ecuid)
		if not tccheck(can_interface):
			die("[!] Please set {} qdisc to pfifo_fast. Now it's too risky to continue...".format(can_interface))

	def tester(self):
		debug("[+] Sending TesterPresent to 0x{:x}... ".format(self.ecuid), end="")
		if self.ecu.UDSTesterPresent():
			debug("OK")
		else:
			die("\n[-] 0x{:x} did not send positive reposnse to our tester message... Aborting".format(self.ecuid))

	def ver(self):
		self.ecu.UDSDiagnosticSessionControl(0x01)
		sleep(2)

		tmp = self.ecu.getHWPartNo()
		debug("\n[?] HWPartNo: {}".format(tmp))

		tmp = self.ecu.getPartNo()
		debug("[?] PartNo: {}".format(tmp))

		debug("[?] Current software: ", end="")
		sw = self.ecu.getStrategy()
		if sw:
			debug(sw)
		else:
			die("\n[-] Unable to get the current strategy id. Aborting")


	def verEx(self):
		self.ecu.UDSDiagnosticSessionControl(0x01)
		sleep(2)

		tmp = self.ecu.getHWPartNo()
		debug("\n[?] HWPartNo: {}".format(tmp))

		tmp = self.ecu.getPartNo()
		debug("[?] PartNo: {}".format(tmp))

		debug("[?] Checking current strategy... ", end="")
		sw = self.ecu.getStrategy()
		if sw:
			debug(sw)
		else:
			die("\n[-] Unable to get the current strategy id. Aborting")

		tmp = self.ecu.UDSReadDataByIdentifier([0xf1, 0x24]).decode('UTF-8')
		debug("[?] Current calibration: {}".format(tmp))

		tmp = self.ecu.getCVN()
		debug("[?] CVN: {}\n".format(tmp))


	def start(self):
		debug("\n[+] Starting Diagnostic Session 0x02... ", end="")
		if self.ecu.UDSDiagnosticSessionControl(0x02): # 0x02
			debug("OK")
		else:
			die("\n[-] Unable to start diagnostic session. Aborting.")
		sleep(1)

		debug("[ ] Unlocking the ECU...")
		res, msg = self.ecu.unlock(0x01) # 0x01
		if res:
			debug(msg)
		else:
			die(msg)


	def upload(self, vbf): # somewhere in here it needs to request multiple downloads for different SBL Blocks
		spinner = ['/','-', '\\', '|']
		fmt = int(vbf.header.get('data_format_identifier', '0x00'), 16)

		for ds in vbf.data: #ds (data structure) in vbf.data?
			debug("\n[ ] Requesting download of 0x{:08x} bytes to 0x{:08x}".format(ds['size'], ds['addr']))
			chunk = self.ecu.UDSRequestDownload(addr=ds['addr'], size=ds['size'], fmt=fmt) #get the expected download byte size from recv
			if not chunk:
				die("[-] Download request failed. Aborting.")
			chunk = int(chunk.hex(), 16) - 2 #minus 2 to make room for the message, I think. Result is 7FE but converted to integer 2046

			num = ceil(ds['size']/chunk) #number is the ceiling size of the download/size of chunk. So 8192/2046, or 5
			for i in range(1, num+1): #for loop while i is between 1 and 6(in this case). So it will run 5 times

				d = ds['data'][(i-1)*chunk : i*chunk] #basically, grab ds data based on the offset of the chunk (7FE), and grab length of one chunk
				debug("\r\t[{}] Sending 0x{:04x} bytes block #{:2d}/{}... ".format(spinner[i%4],len(d), i, num), end="")
				if self.ecu.UDSTransferData(i%256, d): # i%256 somehow represents which iteration, ie. 34 02. Why the modulo is needed is beyond me
					pass
				else:
					die("\n[-] Failed. Aborting.")
			print('OK\r\t[+')

			if self.ecu.UDSRequestTransferExit():
				debug("[+] Transfer done.")
			else:
				die("[-] Transfer failed. Aborting.")


	def erase(self, vbf):
		if not vbf.header.get('erase'):
			return

		if type(vbf.header.get('erase')[0]) != list:
			vbf.header['erase'] = [vbf.header['erase']]

		debug("\n[+] Erasing memory:")
		for ds in vbf.header.get('erase'):
			addr = int(ds[0], 16)
			size = int(ds[1], 16)

			debug("\t0x{:08x}: 0x{:x} bytes... ".format(addr, size), end="")
			if self.ecu.erase(addr, size):
				debug("OK")
			else:
				die("[!] Unable to wipe memroy. Rather be safe than sorry. Bye...")


	def testerloop(self):
		while  True:
			self.ecu.UDSTesterPresent()
			sleep(1)


	def flash_sbl(self):
		self.upload(self.sbl)
		debug("\n[+] Calling SBL at {}... ".format(self.sbl.header['call']), end="")
		if self.ecu.SBLcall(int(self.sbl.header['call'], 16)):
			debug("OK")
		else:
			die("[-] Executing SBL failed. Aborting.")


	def flash_exe(self):
		self.erase(self.exe)
		self.upload(self.exe)
		self.ecu.commit()


	def flash_data(self):
		self.erase(self.data)
		self.upload(self.data)
		self.ecu.commit()


	def flash(self):
		if self.sbl:
			debug("\n[*] Loading SBL...")
			self.flash_sbl()

		if self.exe:
			debug("\n[*] Flashing EXE...")
			self.flash_exe()

		if self.data:
			debug("\n[*] Flashing DATA...")
			self.flash_data()


def usage(str):
	print('usage: {} interface sbl_file.vbf strategy_file.vbf calibration_file.vbf'.format(str))


def debug(str, end="\n"):
	print(str, end=end)
	sys.stdout.flush()


def die(str):
	print(str)
	#sys.exit(-1)


if __name__ == '__main__':

	iface = sys.argv[1]

	try:
		PID_Requester = FordCANSniffer(can_interface=iface, ecuid=0x7e0)
		RPMsniffer = FordCANSniffer(can_interface=iface, ecuid=0x1F9) #RPM ID 201 minus 0x08
	except OSError as e:
		enum = e.args[0]
		if enum == 19:
			die('[!] Unable to open device {}'.format(iface))
		if enum == 99:
			die('[!] Unable to assign ecu address = {}'.format(iface))
		die(e)

	debug("\n[+] Successfully opened {}".format(iface))

	app.run(debug=True)

from hashlib import sha1
from struct import pack, unpack
from collections import namedtuple
import os

def read_file(file):
	try:
		with open(file, "rb") as f:
			return f.read()
	except FileNotFoundError:
		return


class asdf_index:
	def __init__(self, GIT_DIR):
		self.git_dir = GIT_DIR
		self.IndexEntry = namedtuple('IndexEntry', ['ctime_s', 'ctime_n', 'mtime_s', 'mtime_n', 'dev', 'ino', 'bit_mode', 'uid', 'gid', 'file_size', 'sha', 'flags', 'path'])


	def read_index(self):
		try:
			if not os.path.exists(f'{self.git_dir}/.git/index'):
				return []

			fields = []

			index = read_file(f'{self.git_dir}/.git/index')

			checksum = sha1(index[:-20]).digest()


			if checksum != index[-20:]:
				print("Invalid index file")
				return

			signature, version, number = unpack('!4sLL', index[:12]) 

			if signature != b'DIRC':
				print(f"Invalid index signature: {signature}")

			if version != 2:
				print(f"Version not supported: {version}")
			data = index[12:-20]

			i = 0
			header_len = 62
			# 62 is the total number of bytes taken up by the hader portion
			while i + header_len < len(data):
				field = unpack('!LLLLLLLLLL20sH', data[i:i+header_len])

				#File name is present after the headers, and it is of variable length, and ends with a \x00
				path = data[i+header_len:data.index(b'\x00', i+header_len)]

				fields.append(self.IndexEntry(*field, path.decode()))

				#The index file is set up so that file name is followed by a /x00 and the entire entry is a multiple of 8
				i += ((header_len + len(path) + 8) // 8) * 8

			return fields

		except FileNotFoundError:
			return []

	def write_index(self, entries):

		os.chdir(self.git_dir)
		
		header = pack('!4sLL', b'DIRC', 2, len(entries))

		data = b''
		for i in entries:
			m = pack('!LLLLLLLLLL20sH', i.ctime_s, i.ctime_n, i.mtime_s, i.mtime_n, i.dev, i.ino, i.bit_mode, i.uid, i.gid, i.file_size, i.sha, i.flags)
			data += m + i.path.encode()
			length = (62 + len(i.path) + 8) // 8 * 8
			data += b'\x00' * (length - 62 - len(i.path))				

		full_data = header+data
		sha = sha1(full_data).hexdigest()
		shap = pack('!20s', bytes.fromhex(sha))
		full_data += shap
		with open(".git/index", "wb") as f:
			f.write(full_data)
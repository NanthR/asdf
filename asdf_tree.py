from collections import namedtuple
import os
from operator import attrgetter

FileStructure = namedtuple('FileStructure', ['parent', 'own'])

def read_file(file):
	try:
		with open(file, "rb") as f:
			return f.read()
	except FileNotFoundError:
		return

class asdf_tree:
	def __init__(self, index_func, cmd_hash_object):
		self.index_func = index_func
		self.cmd_hash_object = cmd_hash_object

	@staticmethod
	def read_tree(content):
		i = 0
		data = ''
		content = content[content.find(b'\x00')+1:]
		while True:
			end = content.find(b'\x00', i)
			if end == -1:
				break
			mode, path = content[i:end].decode().split()
			digest = content[end+1:end+21].hex()
			data += f"{mode} {digest}    {path}\n"
			i = end + 21

		return data


	def set_up_tree(self):
		data = self.index_func.read_index()
		full_data = b''
		files = []
		for i in data:
			path = i.path
			while True:
				t = FileStructure(os.path.dirname(path), path)
				if t not in files:
					files.append(t)
				if os.path.dirname(path) == "":
					break
				temp = path.split("/")
				temp.pop()
				path = '/'.join(temp)

		files = sorted(files, key=attrgetter('parent'))

		return self.write_tree(files, '')
				

	def write_tree(self, files, parent):
		fields = self.index_func.read_index()
		data = b''
		for i in files:
			if os.path.isdir(i.own):
				if i.parent == parent:
					sha = bytes.fromhex(self.write_tree([j for j in files if j.parent != parent], i.own))
					data += f'040000 {i.own.replace(parent + "/", "")}'.encode()+b'\x00'
					data += sha
			else:
				if i.parent == parent:
					sha = next(j.sha for j in fields if j.path == i.own)
					mode = os.stat(i.own).st_mode
					if oct(mode)[2:][3] == "7":
						mode = 100755
					else:
						mode = 100644
					path = i.own.replace(i.parent + "/", "")
					data += f'{mode} {path}'.encode() + b'\x00'
					data += sha
		
		return self.cmd_hash_object(data, 'tree', True, False)
from os import chdir, path, walk, getcwd
from pydoc import pager
from zlib import decompress
from datetime import datetime
from re import split

class asdf_status:
	
	def __init__(self, GIT_DIR, index_func, find_missing, cmd_hash_object, read_tree):
		self.index_func = index_func
		self.GIT_DIR = GIT_DIR
		self.find_missing = find_missing
		self.cmd_hash_object = cmd_hash_object
		self.read_tree = read_tree

	
	def cmd_ls_files(self, stage=False):
		paths = self.index_func.read_index()
		if not stage:
			for i in paths:
				print(i.path)

		else:
			for i in paths:
				print(oct(i.bit_mode)[2:], i.sha.hex(), i.path)


	def cmd_cat_file(self, args):
		with open(f"{self.GIT_DIR}/.git/objects/{args.hash[:2]}/{args.hash[2:]}", "rb") as f:
			content = decompress(f.read())
			assert content.split()[0].decode() in ['commit', 'tree', 'blob']
			
			if args.type:
				print(f"Type: {content.split()[0].decode()}")
			
			if args.size:
				print(split(b"\x00", content.split()[1], 1)[0].decode())

			if args.print:
				print(f"Content:")
				if content.split()[0].decode() == "tree":
					print(self.read_tree(content))
				else:
					null_index = content.index(b'\x00')
					print(content[null_index+1:].decode())



	def cmd_status(self):

		chdir(self.GIT_DIR)

		print()

		try:
			with open(f"{self.GIT_DIR}/.gitignore", "r") as f:
				ignored = f.read().strip().split('\n')
		except:
			ignored = []


		fields = self.index_func.read_index()
		untracked = []
		added = []
		modified = []

		try:
			with open(f"{self.GIT_DIR}/.git/refs/heads/master", "rb") as f:
				parent = f.read().strip().decode()
			commits = list(self.find_missing(parent, "0"*40))
			commits.sort()
		except FileExistsError:
			commits = []

		for i in fields:
			if i.sha.hex() not in commits:
				added.append(f"    \033[92m {i.path}\033[00m")
			if path.exists(f'{self.GIT_DIR}/{i.path}'):
				if i.sha.hex() != self.cmd_hash_object(path.abspath(i.path), 'blob', write=False):
					modified.append(f"modified: {i.path}")
			else:
				modified.append(f"deleted: {i.path}")
		if added:
			print("Changes to be committed:")
			print('  (use "asdf commit" to commit the changes)')
			for i in added:
				print(i)
		else:
			print("\033[92mNo changes to be committed\033[00m")
		
		if modified:
			print("\nChanges not staged for commit")
			print('  (use "asdf add <file>" to include in what will be committed)')
			print('  (use "asdf restore <file>" to resore the file to its last added stage)')
			for i in modified:
				print(f"    \033[91m {i}\033[00m")
		
		exclude = set(['.git'])
		for i in ignored:
			if path.isdir(self.GIT_DIR + "/" + i):
				exclude.add(i)

		for root, dirs, files in walk(getcwd()):
			dirs[:] = [d for d in dirs if d not in exclude]
			for i in files:
				if not any(j.path == (f"{root}/{i}").replace(self.GIT_DIR + "/", "") for j in fields):
					untracked.append(f"{root}/{i}")

		untracked = [i.replace(self.GIT_DIR + "/", "") for i in untracked if i.replace(self.GIT_DIR + "/", "") not in ignored]
		
		if untracked:
			print("\nUntracked files:")
			print('  (use "asdf add <file>" to include in what will be committed)')
			for i in untracked:
				print(f"    \033[91m{i}\033[00m")

		print()

	def cmd_log(self):

		#Log of commits

		chdir(self.GIT_DIR)

		if not path.exists(f".git/commits"):
			print("No commits have been made")
			return
		with open(f".git/commits", "rb") as f:
			commits = f.read().strip().split(b'\n')
		data = ""
		for i in commits:
			i = i.decode()
			data += f"\033[33mcommit {i} \033[00m\n"
			with open(path.join('.git','objects', i[:2], i[2:]), "rb") as f:
				content = decompress(f.read()).decode()
			start = content.find('author')
			end = content.find('\n',start)
			author_details = content[start:end].split()
			data += f"Author: {author_details[1]} {author_details[2]}\n"
			date = datetime.fromtimestamp(int(author_details[3])).strftime("%A %B %d %I:%M:%S %Y")
			data += f"Date:   {date} {author_details[4]}\n"		
			message = content[content.find('\n\n'):-1].strip()
			data+= f"\n      {message}\n"
		pager(data)
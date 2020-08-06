import argparse, collections, stat, difflib, readline, hashlib, os, configparser, re, struct, sys, time, requests, zlib, datetime, time
from operator import attrgetter
from dotenv import load_dotenv
from getpass import getpass
from shutil import rmtree

load_dotenv()

IndexEntry = collections.namedtuple('IndexEntry', ['ctime_s', 'ctime_n', 'mtime_s', 'mtime_n', 'dev', 'ino', 'bit_mode', 'uid', 'gid', 'file_size', 'sha', 'flags', 'path'])

Types = {"commit": 1, "tree": 2, "blob": 3}

#ONLY WORKS WITH ONE MAIN FOLDER. FOLDERS INSIDE MAIN FOLDER ARE NOT SUPPORTED

def default_config():
	config = configparser.ConfigParser()

	config.add_section("core")
	config.set("core", "repositoryformatversion", "0")
	config.set("core", "filemode", "false")
	config.set("core", "bare", "false")

	return config

def cmd_init(repo=os.getcwd()):
	if os.path.exists(os.path.join(repo, '.git')):
		print(f"Reinitialized exisiting Git repository in {os.path.join(repo, '.git')}")
	else:
		os.mkdir(os.path.join(repo,".git"))
		author = input('Enter author name: ')
		author_email = input('Enter author email: ')

		with open(".env", "w") as f:
			f.write(f'author = {author}\nauthor_email = {author_email}\n')

		print(f'Initialized repo at {repo}')
	for name in ['objects', 'refs', 'refs/heads']:
		path = os.path.join(repo, '.git', name)
		if not os.path.exists(path):
			os.mkdir(path)
	if not os.path.exists('.git/HEAD'):
		with open(".git/HEAD", "w+") as f:
			f.write('ref: refs/heads/master')
	if not os.path.exists('.git/config'):
		with open(".git/config", "w+") as f:
			config = default_config()
			config.write(f)
	if not os.path.exists('.git/refs/remotes'):
		os.mkdir('.git/refs/remotes')


def cmd_hash_object(file, object_type, write=True, filew=True):
	if filew:
		data = read_file(file)
	else:
		data = file

	header = f'{object_type} {len(data)}'.encode()
	full_data = header+b'\x00'+data
	sha1 = hashlib.sha1(full_data).hexdigest()

	if write:
		path = os.path.join('.git', 'objects', sha1[:2], sha1[2:])
		if not os.path.exists(path):
			os.makedirs(os.path.dirname(path), exist_ok="True")
			with open(path, "wb") as f:
				f.write(zlib.compress(full_data))
	return sha1

def read_file(file):
	try:
		with open(file, "rb") as f:
			return f.read()
	except FileNotFoundError:
		return


def read_index():
	try:
		if not os.path.exists('.git/index'):
			return []

		fields = []

		index = read_file(os.path.join('.git', 'index'))

		checksum = hashlib.sha1(index[:-20]).digest()


		if checksum != index[-20:]:
			print("Invalid index file")
			return

		signature, version, number = struct.unpack('!4sLL', index[:12]) 

		if signature != b'DIRC':
			print(f"Invalid index signature: {signature}")

		if version != 2:
			print(f"Version not supported: {version}")
		data = index[12:-20]

		i = 0
		# 62 is the total number of bytes taken up by the hader portion
		while i + 62 < len(data):
			field = struct.unpack('!LLLLLLLLLL20sH', data[i:i+62])

			#File name is present after the headers, and it is of variable length, and ends with a \x00
			path = data[i+62:data.index(b'\x00', i+62)]

			fields.append(IndexEntry(*field, path.decode()))

			#The index file is set up so that file name is followed by a /x00 and the entire entry is a multiple of 8
			i += ((62 + len(path) + 8) // 8) * 8

		return fields

	except FileNotFoundError:
		return []


def cmd_add(files):
	present = read_index()
	entries = [i for i in present if i.path not in files]
	
	for i in files:
		st = os.stat(i)
		sha1 = cmd_hash_object(i, 'blob')
		#Is a 16 bit field. The remaining bits are set to 0, since this version doesn't deal with merge conflicts and such; Last 12 bits are len(path) provided
		flag = len(i.encode())
		entries.append(IndexEntry(int(st.st_ctime), 0, int(st.st_mtime), 0, st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size, bytes.fromhex(sha1), flag, i))
	entries = sorted(entries, key=attrgetter('path'))
	write_index(entries)


def write_index(entries):
	header = struct.pack('!4sLL', b'DIRC', 2, len(entries))

	data = b''
	for i in entries:
		m = struct.pack('!LLLLLLLLLL20sH', i.ctime_s, i.ctime_n, i.mtime_s, i.mtime_n, i.dev, i.ino, i.bit_mode, i.uid, i.gid, i.file_size, i.sha, i.flags)
		data += m + i.path.encode()
		length = (62 + len(i.path) + 8) // 8 * 8
		data += b'\x00' * (length - 62 - len(i.path))				

	full_data = header+data
	sha = hashlib.sha1(full_data).hexdigest()
	shap = struct.pack('!20s', bytes.fromhex(sha))
	full_data += shap
	with open(".git/index", "wb") as f:
		f.write(full_data)



def parent_hash():
	if os.path.exists('.git/refs/heads/master'):
		return read_file('.git/refs/heads/master')
	else:
		return None


def cmd_ls_files(stage=False):
	paths = read_index()
	if not stage:
		for i in paths:
			print(i.path)

	else:
		for i in paths:
			print(i.bit_mode, i.sha.hex(), i.path)


def cmd_cat_file(*args):
	with open(os.path.join('.git', 'objects', args[0].hash[:2], args[0].hash[2:]), "rb") as f:
		content = zlib.decompress(f.read())
		assert content.split()[0].decode() in ['commit', 'tree', 'blob']
		
		if args[0].type:
			print(f"Type: {content.split()[0].decode()}")
		
		if args[0].size:
			print(re.split(b"\x00", content.split()[1], 1)[0].decode())

		if args[0].print:
			print(f"Content:")
			if content.split()[0].decode() == "tree":
				print(read_tree(content))
			else:
				null_index = content.index(b'\x00')
				print(content[null_index+1:].decode())



def cmd_commit(message):
	if not message:
		message = input("Enter the commit messge: ")

	treeSha = write_tree()
	parent = parent_hash()

	data = f'tree {treeSha}\n'.encode()

	if parent:
		data += b'parent '+parent

	date_seconds = int(time.mktime(datetime.datetime.now().timetuple()))
	tz = -time.timezone

	m = abs(tz)
	timezone = str(m//3600).rjust(2,'0')
	timezone += str((m%3600)//60).rjust(2,'0')
	if tz < 0:
		timezone = '-'+timezone
	else:
		timezone = '+'+timezone

	data += f"author {os.getenv('author')} <{os.getenv('author_email')}> {date_seconds} {timezone}\n".encode()

	if not os.getenv('committer'):
		committer = input("Enter committer name: ")
		committer_email = input("Enter committer email: ")
		with open(".env", "a+") as f:
			f.write(f'committer = {committer}\ncommitter_email = {committer_email}\n')
		load_dotenv()

	data += f"committer {os.getenv('committer')} <{os.getenv('committer_email')}> {date_seconds} {timezone}\n\n".encode()


	data += message.encode()+b'\n'

	sha1 = cmd_hash_object(data, 'commit', filew=False)

	with open(".git/refs/heads/master", "wb") as f:
		f.write((sha1+'\n').encode())

	with open(".git/commits", "ab+") as f:
		f.write((sha1+'\n').encode())

	return sha1



def read_tree(content):
	null_index = content.find(b'\x00')
	content = content[null_index+1:]
	content = content.split(b' ')
	data = ""
	mode = content[0].decode()
	for i in range(1,len(content)):
		null_index = content[i].find(b'\x00')
		name = content[i][:null_index]
		hashmode = content[i][null_index+1:]
		Hash = hashmode[:20].hex()
		data += f"{mode} {Hash}    {name.decode()}\n"
	return data


def write_tree():
	data = read_index()
	full_data = b''
	for i in data:
		full_data += f"{int(oct(i.bit_mode)[2:])} {i.path}".encode()+b"\x00"
		full_data += i.sha

	return cmd_hash_object(full_data, 'tree', True, False)


def cmd_status():
	print()
	
	files = os.listdir()
	files.remove('.git')
	

	if os.path.isfile('.gitignore'):
		with open(".gitignore", "r") as f:
			ignored_files = f.read().strip().split('\n')
		files = [i for i in files if i not in ignored_files]

	fields = read_index()

	if os.path.isfile('.git/refs/heads/master'):
		with open(".git/refs/heads/master", "rb") as f:
			commit_hash = f.read().strip().decode()
		with open(f".git/objects/{commit_hash[:2]}/{commit_hash[2:]}", "rb") as f:
			tree_hash = re.split(b'\x00', zlib.decompress(f.read()), 1)[1].split(b' ')[1].split(b'\n')[0].decode()
		with open(f".git/objects/{tree_hash[:2]}/{tree_hash[2:]}", "rb") as f:
			m = zlib.decompress(f.read())
		# print(m)
		tree = read_tree(m).strip().split('\n')
		tree_dict = {}
		for i in tree:
			tree_dict[i.split()[2]] = i.split()[1]
		changed_files = []
		not_for_commit = []

		for i in fields:
			files.remove(i.path)
			if i.path in tree_dict.keys():
				if tree_dict[i.path] == i.sha.hex():
					pass
				else:
					changed_files.append(f"modified: {i.path}")
			else:
				changed_files.append(f"new file: {i.path}")
			
			if i.sha.hex() != cmd_hash_object(i.path, 'blob', False, True):
				not_for_commit.append(i.path)

		if changed_files:
			print("Changes to be committed")
			for i in changed_files:
				print(f"      \033[92m {i}\033[00m")
			print()

		if not_for_commit:
			print("Changes not staged for commit")
			print('  (use "asdf add <file>" to add the changes to the index)')
			print('  (use "asdf restore <file>" to discard changes in the working directory')
			for i in not_for_commit:
				print(f"      \033[91m modified: {i}\033[00m")
			print()

		if files:
			print("Untracked files:")
			print('  (use "asdf add <file>" to add them to the index)')
			files.sort()
			for i in files:
				print(f"      \033[91m {i}\033[00m")
			


	else:
		if fields:
			changed_fields = []
			print("Changes to be committed")
			for i in fields:
				if i.sha.hex() != cmd_hash_object(i.path, 'blob', False, True):
					changed_fields.append(i.path)
				files.remove(i.path)
				print(f"      \033[92m new file: {i.path}\033[00m")
			print()
			if changed_fields:
				print("Changes not staged for commit:")
				print('  (use "asdf add <file>" to update what will be committed)')
				print('  (use "asdf restore <file>" to discard changes in the working directory')
				for i in changed_fields:
					print(f"      \033[91m modified: {i}\033[00m")
				print()
		if files:
			print("Untracked files:")
			print('  (use "asdf add <file>" to add them to the index)')
			for i in files:
				print(f"      \033[91m {i}\033[00m")
	
	print()

def cmd_restore(file):
	fields = read_index()
	sha = [i.sha for i in fields if i.path == file][0].hex()
	with open(f".git/objects/{sha[:2]}/{sha[2:]}", "rb") as f:
		data = re.split(b'\x00', zlib.decompress(f.read()), 1)[1]
	with open(file, "w") as f:
		f.write(data.decode())


def cmd_log():
	if not os.path.exists(".git/commits"):
		print("No commits have been made")
		return
	with open(".git/commits", "rb") as f:
		commits = f.read().strip().split(b'\n')
	for i in commits:
		i = i.decode()
		print(f"\033[33mcommit {i} \033[00m")
		with open(os.path.join('.git','objects', i[:2], i[2:]), "rb") as f:
			content = zlib.decompress(f.read()).decode()
		start = content.find('author')
		end = content.find('\n',start)
		author_details = content[start:end].split()
		print(f"Author: {author_details[1]} {author_details[2]}")
		date = datetime.datetime.fromtimestamp(int(author_details[3])).strftime("%A %B %d %I:%M:%S %Y")
		print(f"Date:   {date} {author_details[4]}")		
		message = content[content.find('\n\n'):-1].strip()
		print(f"\n      {message}\n")

def cmd_remote(args):
	
	if args.rsub == "add":
		os.mkdir(f".git/refs/remotes/{args.name}")
		config = configparser.ConfigParser()
		config.add_section(f'remote "{args.name}"')
		config.set(f'remote "{args.name}"', "url", args.url)
		config.set(f'remote "{args.name}"', "fetch", f"+refs/heads/*:refs/remotes/{args.name}/*")
		with open(".git/config", "a+") as f:
			config.write(f)

	elif args.rsub == "rm":
		rmtree(f'.git/refs/remotes/{args.name}')
		config = configparser.ConfigParser()
		with open(".git/config", "r") as f:
			config.readfp(f)
		if f'remote "{args.name}"' in config.sections():
			config.remove_section(f'remote "{args.name}"')
			with open(".git/config", "w") as f:
				config.write(f)


def cmd_push(args):

	config = configparser.ConfigParser()


	if not os.path.exists(".git/commits"):
		print("No commits yet")
		return

	if args.name:
		name = args.name
	else:
		name = "origin"

	if args.branch:
		branch = args.branch
	else:
		branch = "master"

	config.read(".git/config")

	if config.has_section(f'remote "{name}"'):
		url = config[f'remote "{name}"']['url']

	else:
		if args.url:
			url = args.url
		else:
			print("No url specified")
			print('  To set a default remote, use "asdf remote add <name> <url>"')
		

	user = input("UserName: ")
	password = getpass("Password: ")


	geturl = url + "/info/refs?service=git-receive-pack"

	get_response = requests.get(geturl, auth=(user, password))

	assert re.match(rb'^[0-9a-f]{4}#', get_response.content)

	get_content = get_response.content.split(b'\n')

	get_content = get_content[1:-1]

	get_content[0] = get_content[0][4:]

	parent = parent_hash().decode().strip()

	remote_hash = read_remote(get_content, branch)

	if parent == remote_hash:
		print("Everything up to date")
		return

	main_header = f'{remote_hash} {parent} refs/heads/{branch}\x00 report-status'.encode()
	main_header = hex(len(main_header) + 5)[2:].rjust(4, '0').encode() + main_header
	main_header += b'\n0000'

	missing = find_missing(parent, remote_hash)

	pack_header = struct.pack("!4sLL", b'PACK', 2, len(missing))

	missing = list(missing)
	missing.sort()

	for i in missing:
		data = zlib.decompress(read_file(f".git/objects/{i[:2]}/{i[2:]}"))
		obj_type = Types[data.split(b' ')[0].decode()]
		space_index = data.find(b' ')
		obj_data_len = data[space_index + 1:]
		null_index = obj_data_len.find(b'\x00')
		obj_len = int(obj_data_len[:null_index])
		obj_data = obj_data_len[null_index+1:]
		if obj_len < 15:
			obj_len_binary = bin(obj_len)[2:].rjust(4, '0')
			obj_type_binary = bin(obj_type)[2:].rjust(3, '0')
			header = '0' + obj_type_binary + obj_len_binary
			header = int(header, 2).to_bytes(1, byteorder = 'big') + zlib.compress(obj_data)
			pack_header += header

		else:
			
			k = len(bin(obj_len)[2:])

			n = 11

			while n - k < 0:
				n += 7

			obj_len_binary = bin(obj_len)[2:].rjust(n, '0')
			obj_type_binary = bin(obj_type)[2:].rjust(3, '0')

			header = [int('1' + obj_type_binary + obj_len_binary[-4:], 2)] 

			now = -4
			length = n - 4

			while length != 7:
				header.append(int('1' + obj_len_binary[now - 7: now], 2))
				now -= 7
				length -= 7

			header.append(int('0' + obj_len_binary[now - 7: now], 2))
			pack_header += bytes(header) + zlib.compress(obj_data)

	pack_header += hashlib.sha1(pack_header).digest()

	content = main_header + pack_header


	post_response = requests.post(url + "/git-receive-pack", data=content, auth=(user, password))



	

def find_missing(parent, remote):
	local_obj = find_commit_objects(parent)
	if remote == "0"*40:
		return local_obj
	remote_obj = find_commit_objects(remote)
	return local_obj - remote_obj

def find_commit_objects(sha):
	objects = {sha}
	commit_data = zlib.decompress(read_file(f".git/objects/{sha[:2]}/{sha[2:]}"))
	commit_data = commit_data[commit_data.index(b'\x00') + 1:]

	commit_split = commit_data.decode().split('\n')

	tree = next(i.split()[1] for i in commit_split if i.startswith('tree '))

	objects.update(tree_data(tree))

	parents = [i.split()[1] for i in commit_split if i.startswith('parent ')]


	for i in parents:
		objects.update(find_commit_objects(i))

	return objects



def tree_data(tree_sha):
	tree_contents = read_tree(zlib.decompress(read_file(f".git/objects/{tree_sha[:2]}/{tree_sha[2:]}")))
	tree_contents = tree_contents.strip().split('\n')
	objects = {tree_sha}
	for i in tree_contents:
		if stat.S_ISDIR(int(i.split()[0])):
			objects.update(tree_data(i.split()[1]))
		else:
			objects.add(i.split()[1])

	return objects

def read_remote(content, branch):
	for i in content:
		if re.split(b'\x00', i.split(b' ')[1], 1)[0] == f'refs/heads/{branch}'.encode():
			return i.split(b' ')[0].decode()[4:]

	return "0"*40

def cmd_clone(url):
	get_response = requests.get(url + "/info/refs?service=git-upload-pack")

	get_content = get_response.content

	assert re.match(rb"^[0-9a-f]{4}# service=git-upload-pack", get_content)

	get_content = get_content.split(b'\n')[2:-1]
	get_content[0] = get_content[0]

	remote_hash = read_remote(get_content, "master")

	print(remote_hash)

	data = f"0032want {remote_hash}\n0032have {'0'*40}\n0000"

	post_response = requests.post(url+"/git-upload-pack", data = data)

	print(post_response.content)






argparser = argparse.ArgumentParser(description="Content tracker")

argsubparsers = argparser.add_subparsers(title="Command", dest="command")


argsubparsers.required = True

argsp = argsubparsers.add_parser("init", help="Initialize repo")
argsp.add_argument('repo', nargs="?", default=os.getcwd(), help="Where to create the repo")

argsp = argsubparsers.add_parser("hash-object", help="Hashing the provided file")
argsp.add_argument('file', help="File to be hashed")
argsp.add_argument('-t', "--type", choices=['commit', 'tree', 'blob'], default='blob', dest='type')
argsp.add_argument('-w', "--write", action='store_true', dest='write', default=True)

argsp = argsubparsers.add_parser("cat-file", help="Display file based on provided hash")
argsp.add_argument("hash", help="Provided hash")
argsp.add_argument("-t", "--type", action = "store_true", dest='type')
argsp.add_argument("-p", "--print", action = "store_true", dest='print')
argsp.add_argument("-s", "--size", action="store_true", dest='size')

argsp = argsubparsers.add_parser("add", help="Add a file to the git index")
argsp.add_argument("files", action="store", help="Files to be added to the index", nargs='+')

argsp = argsubparsers.add_parser("write-index", help="Add a file to .git/index")
argsp.add_argument("file", help='File to be written')

argsp = argsubparsers.add_parser("ls-files", help="Lists out files that have been added to git index")
argsp.add_argument("-s", "--stage", dest='stage', action="store_true")

argsp = argsubparsers.add_parser("commit", help="Commits the files in the index")
argsp.add_argument("-m", "--message", dest='msg')

argsp = argsubparsers.add_parser("status", help="Difference between index and current HEAD commit")

argsp = argsubparsers.add_parser("log", help="Shows the commit logs")

argsp = argsubparsers.add_parser("restore", help="Restores the files to the last add command")
argsp.add_argument("file")

argsp = argsubparsers.add_parser("push")
argsp.add_argument("name")
argsp.add_argument("branch")

argsp = argsubparsers.add_parser('remote')
argdp = argsp.add_subparsers(title = "sub", dest="rsub")
argfp = argdp.add_parser("add")
argfp.add_argument("name")
argfp.add_argument("url")
argfp = argdp.add_parser("rm")
argfp.add_argument("name")

argsp = argsubparsers.add_parser("push", help="Used to push the local repository")
argsp.add_argument("-n", "--name", dest="name")
argsp.add_argument("-b", "--branch", dest="branch")
argsp.add_argument("url", nargs="?")

argsp = argsubparsers.add_parser("clone")
argsp.add_argument("url")


def main(argv=sys.argv[1:]):
	args = argparser.parse_args(argv)

	if args.command == "init" : cmd_init(args.repo)
	if args.command == "hash-object" : cmd_hash_object(args.file, args.type, args.write)
	if args.command == "cat-file" : cmd_cat_file(args)
	if args.command == "add" : cmd_add(args.files)
	if args.command == "write-index" : write_index(args.file)
	if args.command == "ls-files" : cmd_ls_files(args.stage)
	if args.command == "commit" : cmd_commit(args.msg)
	if args.command == "test" : cmd_test()
	if args.command == "status" : cmd_status()
	if args.command == "log" : cmd_log()
	if args.command == "restore" : cmd_restore(args.file)
	if args.command == "remote" : cmd_remote(args)
	if args.command == "push" : cmd_push(args)
	if args.command == "clone" : cmd_clone(args.url)
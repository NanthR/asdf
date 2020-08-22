import argparse, collections, stat, hashlib, os, configparser, re, struct, sys, time, requests, zlib, datetime
from dotenv import load_dotenv
from getpass import getpass
from dateutil.parser import parse
from base64 import b64decode
from pytz import timezone
from asdf_index import asdf_index
from asdf_tree import asdf_tree
from asdf_remote import asdf_remote
from asdf_missing import asdf_missing
from asdf_status import asdf_status
from operator import attrgetter

load_dotenv()

global GIT_DIR
global index_func
global tree_func
global remote_func
global missing_func
global status_func

Types = {"commit": 1, "tree": 2, "blob": 3}

def read_file(file):
	try:
		with open(file, "rb") as f:
			return f.read()
	except FileNotFoundError:
		return


def check_git():
	
	#Checks if the current directory is a git directory

	present = os.getcwd()
	if ".git" in os.listdir():
		return present
	while present != "/":
		present = os.path.dirname(present)
		if ".git" in os.listdir(present):
			return present
	print("\033[91m ERROR: Not a git repository\033[00m")
	sys.exit()

	

def default_config():

	#Writes the default config for the directory

	config = configparser.ConfigParser()

	config.add_section("core")
	config.set("core", "repositoryformatversion", "0")
	config.set("core", "filemode", "false")
	config.set("core", "bare", "false")

	return config

def cmd_init(args):

	repo = args.repo
	if os.path.exists(os.path.join(repo, '.git')):
		print(f"Reinitialized exisiting Git repository in {os.path.join(repo, '.git')}")
	else:
		os.mkdir(os.path.join(repo,".git"))

		if args.author_name:
			author = args.author_name
		else:
			author = input('Enter author name: ')
		
		if args.author_email:
			author_email = args.author_email	
		else:
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



def cmd_add(files):
	present = index_func.read_index()
	
	files = [os.path.abspath(i).replace(GIT_DIR + "/", "") for i in files]

	entries = [i for i in present if i.path not in files]

	os.chdir(GIT_DIR)
	
	for i in files:
		st = os.stat(i)
		sha1 = cmd_hash_object(i, 'blob')
		#Is a 16 bit field. The remaining bits are set to 0, since this version doesn't deal with merge conflicts and such; Last 12 bits are len(path) provided
		flag = len(i.encode())
		if oct(st.st_mode)[2:][3] == "7":
			mode = 33261
		else:
			mode = 33188
		entries.append(index_func.IndexEntry(int(st.st_ctime), 0, int(st.st_mtime), 0, st.st_dev, st.st_ino, mode, st.st_uid, st.st_gid, st.st_size, bytes.fromhex(sha1), flag, i))
	entries = sorted(entries, key=attrgetter('path'))
	index_func.write_index(entries) 


def cmd_commit(message):

	os.chdir(GIT_DIR)

	if not message:
		message = input("Enter the commit messge: ")

	treeSha = tree_func.set_up_tree()
	parent = parent_hash()

	data = f'tree {treeSha}\n'.encode()


	if parent:
		data += b'parent ' + parent

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


def cmd_hash_object(file, object_type, write=True, filew=True):
	if filew:
		data = read_file(file)
	else:
		data = file

	header = f'{object_type} {len(data)}'.encode()
	full_data = header+b'\x00'+data
	sha1 = hashlib.sha1(full_data).hexdigest()

	if write:
		path = f'.git/objects/{sha1[:2]}/{sha1[2:]}'
		if not os.path.exists(path):
			os.makedirs(os.path.dirname(path), exist_ok="True")
			with open(path, "wb") as f:
				f.write(zlib.compress(full_data))
	return sha1


def parent_hash():
	if os.path.exists('.git/refs/heads/master'):
		return read_file('.git/refs/heads/master')
	else:
		return None


def cmd_restore(file):

	#Restores a file in the index to its last added stage

	fields = index_func.read_index()
	sha = [i.sha for i in fields if i.path == file][0].hex()
	with open(f"{GIT_DIR}/.git/objects/{sha[:2]}/{sha[2:]}", "rb") as f:
		data = re.split(b'\x00', zlib.decompress(f.read()), 1)[1]
	with open(file, "w") as f:
		f.write(data.decode())

def cmd_ls_remote(args):

	os.chdir(GIT_DIR)
	config = configparser.ConfigParser()
	config.read(".git/config")

	if args.name:
		name = args.name
	else:
		name = "origin"

	if config.has_section(f'remote "{name}"'):
		url = config[f'remote "{name}"']['url']

	else:
		if args.url:
			url = args.url
		else:
			print("No url specified")
			print('  To set a default remote, use "asdf remote add <name> <url>"')
			return

	get_url = url + "/info/refs?service=git-upload-pack"
	resp = requests.get(get_url)

	content = resp.content
	if content == b'Repository not found.':
		user = input("Enter your username: ")
		password = getpass(prompt="Enter your password: ")
		resp = requests.get(geturl, auth=(user, password))
		content = resp.content

	if content.split(b'\n')[1] == b"00000000":
		print("No commits on remote")
		return

	null_index = content.split(b'\n')[1].find(b'\x00')
	HEAD = content.split(b'\n')[1][8:null_index]
	print(HEAD.decode())
	new_line = content.find(b'\n', null_index)
	data = content[new_line + 1 :].split(b'\n')
	for i in data:
		if i == b"0000":
			break
		else:
			print(i[4:].decode())

def cmd_push(args):

	os.chdir(GIT_DIR)
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
			return
		

	user = input("UserName: ")
	password = getpass("Password: ")


	geturl = url + "/info/refs?service=git-receive-pack"

	get_response = requests.get(geturl, auth=(user, password))

	assert re.match(rb'^[0-9a-f]{4}#', get_response.content)

	get_content = get_response.content.split(b'\n')

	get_content = get_content[1:-1]

	get_content[0] = get_content[0][4:]

	parent = parent_hash().decode().strip()

	remote_hash = missing_func.read_remote(get_content, branch)

	if parent == remote_hash:
		print("Everything up to date")
		return

	main_header = f'{remote_hash} {parent} refs/heads/{branch}\x00 report-status'.encode()

	#pkt-line formatting
	main_header = hex(len(main_header) + 5)[2:].rjust(4, '0').encode() + main_header
	main_header += b'\n0000'

	missing = missing_func.find_missing(parent, remote_hash)

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

	if post_response.content.split(b'\n')[0] == b"000eunpack ok":
		print(f"Successfully pushed to {url}")

	else:
		print("ERROR")

	with open(f".git/refs/remotes/{name}/{branch}", "wb") as f:
		f.write(parent.encode()) 



def cmd_clone(url):

	get_response = requests.get(url + "/info/refs?service=git-upload-pack")

	get_content = get_response.content

	assert re.match(rb"^[0-9a-f]{4}# service=git-upload-pack", get_content)

	get_content = get_content.split(b'\n')[2:-1]
	get_content[0] = get_content[0]

	remote_hash = read_remote(get_content, "master")

	owner = url.split('/')[-2]
	repo = url.split('/')[-1].split('.')[0]

	api = f"https://api.github.com/repos/{owner}/{repo}/git"

	response = requests.get(api + f"/commits/{remote_hash}")

	response_json = response.json()

	
	with open(".env", "w") as f:
		f.write(f"author = {response_json['author']['name']}\nauthor_email = {response_json['author']['email']}")

	cmd_init(argparse.Namespace(author_name=response_json['author']['name'], author_email=response_json['author']['email'], repo=os.getcwd()))

	with open(".git/refs/heads/master", "wb") as f:
		f.write(f"{response_json['sha']}\n".encode())

	os.makedirs('.git/refs/remotes/origin')

	with open(".git/refs/remotes/origin/master", "wb") as f:
		f.write(f"{response_json['sha']}\n".encode())

	api_commit(response.json(), owner, repo)

	tree_data = requests.get(response_json['tree']['url'])

	tree_json = tree_data.json()

	files = [i['path'] for i in tree_json['tree']]

	cmd_add(files)


def api_commit(response_data, owner, repo):
	
	
	while True:
		flag = 0
		author_name = response_data['author']['name']
		author_email = response_data['author']['email']
		committer_name = response_data['committer']['name']
		committer_email = response_data['committer']['email']
		treeSha = response_data['tree']['sha']
		data = f'tree {treeSha}\n'.encode()
		if response_data['parents'] != []:
			parent = response_data['parents'][0]['sha']
			data += f'parent {parent}\n'.encode()
		else:
			flag = 1
		zone = '+0530'
		author_time = int(time.mktime(parse(response_data['author']['date'] + "+0000").astimezone(timezone('Asia/Kolkata')).timetuple()))
		committer_time = int(time.mktime(parse(response_data['committer']['date'] + "+0000").astimezone(timezone('Asia/Kolkata')).timetuple()))

		data += f"author {author_name} <{author_email}> {author_time} {zone}\n".encode()
		data += f"committer {committer_name} <{committer_email}> {committer_time} {zone}\n\n".encode()

		data += f'{response_data["message"]}\n'.encode()

		with open(".git/commits", "ab+") as f:
			f.write((response_data['sha'] + '\n').encode())

		cmd_hash_object(data, 'commit', write=True, filew=False)

		api_tree(response_data['tree']['url'])

		if flag == 1:
			break

		response_data = requests.get(f'https://api.github.com/repos/{owner}/{repo}/git/commits/{response_data["parents"][0]["sha"]}').json()


		
def api_tree(tree_url):
	response_data = requests.get(tree_url).json()
	data = b''
	tree_data = response_data['tree']
	for i in tree_data:
		api_blob(i['url'], i['path'])
		if i['mode'] == "100644":
			i['mode'] = "100664"
		elif i['mode'] == "100755":
			os.chmod(i['path'], 0o700)
		data += f"{i['mode']} {i['path']}".encode() + b'\x00'
		data += bytes.fromhex(i['sha'])	 		

	cmd_hash_object(data, 'tree', True, False)


def api_blob(blob_url, path):
	response_data = requests.get(blob_url).json()
	data = b64decode(response_data['content']).decode()
	with open(path, 'w') as f:
		f.write(data)

	cmd_hash_object(data.encode(), 'blob', True, False)



def bash_rm():

	#Used to provide autocomplete options for asdf rm

	fields = read_index()
	for i in fields:
		print(i.path, end = " ")
	print()


argparser = argparse.ArgumentParser(description="Content tracker")


argsubparsers = argparser.add_subparsers(title="Command", dest="command")

argsubparsers.required = True

argsp = argsubparsers.add_parser("init", help="Initialize repo")
argsp.add_argument('repo', nargs="?", default=os.getcwd(), help="Where to create the repo")
argsp.add_argument('-n', '--name', dest = 'author_name', help = "Name of the author")
argsp.add_argument('-e', '--email', dest = 'author_email', help = "The author's email")

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

argsp = argsubparsers.add_parser('remote', help="Adding or removing remote repo info")
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

argsp = argsubparsers.add_parser("ls-remote", help="Prints commit info from remote repo")
argsp.add_argument("-u", "--url", dest="url")
argsp.add_argument("-n", "--name", dest="name")

argsp = argsubparsers.add_parser("bash_rm")


def main(argv=sys.argv[1:]):
	args = argparser.parse_args(argv)
	global GIT_DIR
	global index_func
	global tree_func
	global remote_func
	global missing_func
	global status_func

	if args.command == "init" : cmd_init(args)
	elif args.command == "clone" : cmd_clone(args.url)
	else:
		GIT_DIR = check_git()
		index_func = asdf_index(GIT_DIR)
		tree_func = asdf_tree(index_func, cmd_hash_object)
		remote_func = asdf_remote(GIT_DIR)
		missing_func = asdf_missing(GIT_DIR, index_func, cmd_hash_object)
		status_func = asdf_status(GIT_DIR, index_func, missing_func.find_missing, cmd_hash_object, tree_func.read_tree)

		if args.command == "hash-object" : cmd_hash_object(args.file, args.type, args.write)
		elif args.command == "cat-file" : status_func.cmd_cat_file(args)
		elif args.command == "add" : cmd_add(args.files)
		elif args.command == "write-index" : write_index(args.file)
		elif args.command == "ls-files" : status_func.cmd_ls_files(args.stage)
		elif args.command == "commit" : cmd_commit(args.msg)
		elif args.command == "status" : status_func.cmd_status()
		elif args.command == "log" : status_func.cmd_log()
		elif args.command == "restore" : cmd_restore(args.file)
		elif args.command == "remote" : remote_func.cmd_remote(args)
		elif args.command == "push" : cmd_push(args)
		elif args.command == "bash_rm" : bash_rm()
		elif args.command == "ls-remote" : cmd_ls_remote(args)
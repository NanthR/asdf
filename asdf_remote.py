import configparser
from shutil import rmtree
from os import mkdir

class asdf_remote:
	def __init__(self, GIT_DIR):
		self.GIT_DIR = GIT_DIR

	def cmd_remote(self, args):
		
		if args.rsub == "add":
			mkdir(f"{self.GIT_DIR}/.git/refs/remotes/{args.name}")
			config = configparser.ConfigParser()
			config.add_section(f'remote "{args.name}"')
			config.set(f'remote "{args.name}"', "url", args.url)
			config.set(f'remote "{args.name}"', "fetch", f"+refs/heads/*:refs/remotes/{args.name}/*")
			with open(f"{self.GIT_DIR}/.git/config", "a+") as f:
				config.write(f)

		elif args.rsub == "rm":
			try:
				rmtree(f'{self.GIT_DIR}/.git/refs/remotes/{args.name}')
			except:
				pass
			config = configparser.ConfigParser()
			with open(f"{self.GIT_DIR}/.git/config", "r") as f:
				config.readfp(f)
			if f'remote "{args.name}"' in config.sections():
				config.remove_section(f'remote "{args.name}"')
				with open(f"{self.GIT_DIR}/.git/config", "w") as f:
					config.write(f)

import zlib, re, stat
from asdf_tree import asdf_tree



def read_file(file):
	try:
		with open(file, "rb") as f:
			return f.read()
	except FileNotFoundError:
		return

class asdf_missing:
	def __init__(self, GIT_DIR, index_func, cmd_hash_object):
		self.GIT_DIR = GIT_DIR
		self.tree_func = asdf_tree(index_func, cmd_hash_object)

	def find_missing(self, parent, remote):
		local_obj = self.find_commit_objects(parent)
		if remote == "0"*40:
			return local_obj
		remote_obj = self.find_commit_objects(remote)
		return local_obj - remote_obj



	def find_commit_objects(self, sha):
		objects = {sha}
		
		commit_data = zlib.decompress(read_file(f"{self.GIT_DIR}/.git/objects/{sha[:2]}/{sha[2:]}"))
		
		commit_data = commit_data[commit_data.index(b'\x00') + 1:]

		commit_split = commit_data.decode().split('\n')

		tree = next(i.split()[1] for i in commit_split if i.startswith('tree '))

		objects.update(self.tree_data(tree))

		parents = [i.split()[1] for i in commit_split if i.startswith('parent ')]


		for i in parents:
			objects.update(self.find_commit_objects(i))

		return objects

	def tree_data(self, tree_sha):
		tree_contents = self.tree_func.read_tree(zlib.decompress(read_file(f"{self.GIT_DIR}/.git/objects/{tree_sha[:2]}/{tree_sha[2:]}")))
		tree_contents = tree_contents.strip().split('\n')
		objects = {tree_sha}
		for i in tree_contents:
			if stat.S_ISDIR(int(i.split()[0], 8)):
				objects.update(self.tree_data(i.split()[1]))
			else:
				objects.add(i.split()[1])

		return objects

	@staticmethod
	def read_remote(content, branch):
		for i in content:
			if re.split(b'\x00', i.split(b' ')[1], 1)[0] == f'refs/heads/{branch}'.encode():
				return i.split(b' ')[0].decode()[4:]

		return "0"*40
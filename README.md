# ASDF

An incomplete (but pretty capable) git clone written in python

### Prerequisite libraries

* requests
	- ``pip install requests``
* pytz
	- ``pip install pytz``

### Notes

* To enable bash autocompletion, run the following from the repository's directory.  
	- ``source ./asdf_completion.bash``
* This does not support directories inside a repository.
* The clone functionality is built with the GitHub API, and hence suffers from rate limitations.
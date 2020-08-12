#!/bin/bash

_asdf_completions()
{
	local cur prev opts
	COMPREPLY=()
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"
	opts="add init hash-object cat-file write-index ls-files commit status log restore push remote clone rm"

	if [[ ${prev} == "./asdf" ]] ; then
		COMPREPLY=( $(compgen -W "${opts}" -- $cur) )
	fi

	case $prev in

		cat-file)
			if [[ ${cur} == -* ]] ; then
				COMPREPLY=( $(compgen -W "-t -p -s" -- $cur) )
			fi
			;;
		restore)
			files=`./asdf bash_rm | tail -n 1`
			COMPREPLY=( $(compgen -W "${files}" -- $cur) )
			;;
		push)
			if [[ ${cur} == -* ]] ; then
				COMPREPLY=( $(compgen -W "-n -b" -- $cur) )
			fi
			;;
		remote)
			COMPREPLY=( $(compgen -W "add rm" -- $cur) )
			;;
		commit)
			if [[ ${cur} == -* ]] ; then
				COMPREPLY=( $(compgen -W "-m" -- $cur))
			fi
			;;	
		rm)
			files=`./asdf bash_rm | tail -n 1`
			COMPREPLY=( $(compgen -W "${files}" -- $cur) )
			;;
		add)
			files=`./asdf bash_add | tail -n 1`
			COMPREPLY=( $(compgen -W "${files}" -- $cur) )
			;;
	esac


}

complete -F _asdf_completions ./asdf
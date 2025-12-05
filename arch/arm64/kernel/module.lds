SECTIONS {
<<<<<<< HEAD
	.plt : { BYTE(0) }
	.init.plt : { BYTE(0) }
	.text.ftrace_trampoline : { BYTE(0) }
=======
	.plt (NOLOAD) : { BYTE(0) }
	.init.plt (NOLOAD) : { BYTE(0) }
	.text.ftrace_trampoline (NOLOAD) : { BYTE(0) }
>>>>>>> v4.14.187
}

#!/usr/bin/env python3
# coding=utf-8
import sys
import stat
import time
import atexit
import shutil
import struct
import tarfile
import os.path
import subprocess

from collections import OrderedDict
from ntfsea import ntfsea, lxattrb, stmode
from utils import Fore, ProgressFileObject, parse_image_arg, probe_wsl, get_label, show_cursor, hide_cursor, draw_progress, clear_progress, escape_ntfs_invalid

try:
	import PySquashfsImage
	havesquashfs = True
except ImportError:
	havesquashfs = False

# handle arguments

imgarg   = ''
runhooks = True
case_sensitive = False

if len(sys.argv) > 1:
	for arg in sys.argv[1:]:
		if arg.lower() == '--no-hooks':
			runhooks = False
		elif arg.lower() == '--case-sensitive':
			case_sensitive = True
		elif not imgarg:
			imgarg = arg

if not imgarg:
	print('usage: ./install.py [--no-hooks] [--case-sensitive] image[:tag] | tarball | squashfs')
	print('\noptions:\n  --no-hooks    Omits running the hook scripts.')
	print('\n  --case-sensitive    [TEST ONLY]Make IO case-sensitive. HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\\obcaseinsensitive must be set to 0 and reboot.')
	exit(-1)

image, tag, fname, label = parse_image_arg(imgarg, True)

# sanity checks

print('%s[*]%s Probing the Linux subsystem...' % (Fore.GREEN, Fore.RESET))

basedir, lxpath = probe_wsl()

user     = ''
isroot   = False
homedir  = ''
homedirw = ''

# somewhat a major issue, stdout and stderr can't be redirected, so this script can't monitor the output
# of any of the launched commands. it can, however, receive the exit status, so that's something, I guess.
# ref: https://github.com/Microsoft/BashOnWindows/issues/2

try:
	subprocess.check_call(['cmd', '/C', lxpath + '\\bash.exe', '-c', 'echo $HOME > /tmp/.wsl_usr.txt; echo $USER >> /tmp/.wsl_usr.txt'])
	out = os.path.join(basedir, 'rootfs/tmp/.wsl_usr.txt')

	if not os.path.isfile(out):
		print('%s[!]%s Failed to get home directory of default user in WSL: Output file %s%s%s not present.' % (Fore.RED, Fore.RESET, Fore.BLUE, out, Fore.RESET))
		exit(-1)

	with open(out) as f:
		homedir  = f.readline().strip()
		homedirw = os.path.join(basedir, homedir.lstrip('/'))

		if len(homedir) == 0 or not os.path.isdir(homedirw):
			print('%s[!]%s Failed to get home directory of default user in WSL: Returned path %s%s%s is not valid.' % (Fore.RED, Fore.RESET, Fore.BLUE, homedirw, Fore.RESET))
			exit(-1)

		user   = f.readline().strip()
		isroot = user == 'root'

	print('%s[*]%s Default user is %s%s%s at %s%s%s.' % (Fore.GREEN, Fore.RESET, Fore.YELLOW, user, Fore.RESET, Fore.BLUE, homedir, Fore.RESET))

	os.unlink(out)

except subprocess.CalledProcessError as err:
	print('%s[!]%s Failed to get home directory of default user in WSL: %s' % (Fore.RED, Fore.RESET, err))
	exit(-1)

# check squashfs prerequisites

fext = os.path.splitext(fname)[-1].lower()

if (fext == '.sfs' or fext == '.squashfs') and not havesquashfs:
	print('%s[!]%s Module %sPySquashfsImage%s is not available. Install it with %spip3 install PySquashfsImage%s for SquashFS support.' % (Fore.RED, Fore.RESET, Fore.GREEN, Fore.RESET, Fore.GREEN, Fore.RESET))
	exit(-1)

# get /etc/{passwd,shadow,group,gshadow} entries

print('%s[*]%s Reading %s/etc/{passwd,shadow,group,gshadow}%s entries for %sroot%s%s...' % (Fore.GREEN, Fore.RESET, Fore.BLUE, Fore.RESET, Fore.YELLOW, Fore.RESET, (' and %s%s%s' % (Fore.YELLOW, user, Fore.RESET) if not isroot else '')))

etcpasswduser  = ''
etcshadowroot  = ''
etcshadowuser  = ''
etcgroupuser   = ''
etcgshadowuser = ''

if not isroot:
	try:
		with open(os.path.join(basedir, 'rootfs', 'etc', 'passwd'), newline='\n') as f:
			for line in f.readlines():
				if line.startswith(user + ':'):
					etcpasswduser = line.strip()

	except OSError as err:
		print('%s[!]%s Failed to open file %s/etc/passwd%s: %s' % (Fore.RED, Fore.RESET, Fore.BLUE, Fore.RESET, err))
		exit(-1)

try:
	with open(os.path.join(basedir, 'rootfs', 'etc', 'shadow'), newline='\n') as f:
		for line in f.readlines():
			if line.startswith('root:'):
				etcshadowroot = line.strip()
			if not isroot and line.startswith(user + ':'):
				etcshadowuser = line.strip()

except OSError as err:
	print('%s[!]%s Failed to open file %s/etc/shadow%s: %s' % (Fore.RED, Fore.RESET, Fore.BLUE, Fore.RESET, err))
	exit(-1)

if not isroot:
	try:
		with open(os.path.join(basedir, 'rootfs', 'etc', 'group'), newline='\n') as f:
			for line in f.readlines():
				if line.startswith(user + ':'):
					etcgroupuser = line.strip()

	except OSError as err:
		print('%s[!]%s Failed to open file %s/etc/group%s: %s' % (Fore.RED, Fore.RESET, Fore.BLUE, Fore.RESET, err))
		exit(-1)

	try:
		with open(os.path.join(basedir, 'rootfs', 'etc', 'gshadow'), newline='\n') as f:
			for line in f.readlines():
				if line.startswith(user + ':'):
					etcgshadowuser = line.strip()

	except OSError as err:
		print('%s[!]%s Failed to open file %s/etc/gshadow%s: %s' % (Fore.RED, Fore.RESET, Fore.BLUE, Fore.RESET, err))
		exit(-1)

if etcshadowroot:
	parts = etcshadowroot.split(':')

	if parts[1] == '*' or parts[1].startswith('!'):
		etcshadowroot = ''
	else:
		etcshadowroot = parts[1]

# enable here for `path` and `SystemRoot` don't always have right case
if case_sensitive:
	try:
		ntfsea.init()
		ntfsea.enableposix()
	except Exception:
		pass

# remove old remnants

if os.path.exists(os.path.join(homedirw, 'rootfs-temp')):
	print('%s[*]%s Removing leftover %srootfs-temp%s...' % (Fore.GREEN, Fore.RESET, Fore.BLUE, Fore.RESET))

	try:
		def retry_rw(operation, name, exc):
			os.chmod(name, stat.S_IWRITE)
			operation(name)

		shutil.rmtree(os.path.join(homedirw, 'rootfs-temp'), onerror = retry_rw)
	except Exception:
		pass

	# ensure it's removed

	if os.path.exists(os.path.join(homedirw, 'rootfs-temp')):
		print('%s[*]%s Failed to remove leftover %srootfs-temp%s.' % (Fore.RED, Fore.RESET, Fore.BLUE, Fore.RESET))
		exit(-1)

# extract archive

print('%s[*]%s Beginning extraction...' % (Fore.GREEN, Fore.RESET))

if fext == '.sfs' or fext == '.squashfs':

	# extract rootfs from SquashFS

	try:
		img  = PySquashfsImage.SquashFsImage(fname)
		path = os.path.join(homedirw, 'rootfs-temp')

		hide_cursor()
		ntfsea.init()

		i = 0
		for file in img.root.findAll():
			name = file.getPath().lstrip('./')
			winpath = path + '/' + escape_ntfs_invalid(name)

			draw_progress(i, img.total_inodes, name)
			i += 1

			try:

				# create directory or extract file

				if file.isFolder():
					os.makedirs(winpath, exist_ok = True)

				else:
					with open(winpath, 'wb') as f:
						f.write(file.getContent())

				# apply lxattrb

				os.chmod(winpath, stat.S_IWRITE)

				attrb = lxattrb.fromsfs(file).generate()
				ntfsea.writeattr(winpath, 'lxattrb', attrb)

			except Exception as err:
				clear_progress()
				print('%s[!]%s Failed to extract %s: %s' % (Fore.YELLOW, Fore.RESET, name, err))
				pass

	finally:
		img.close()
		clear_progress()
		show_cursor()

else:

	# the TarFile class has a list of supported compression methods, but this is stored
	# in a dictionary, which somehow becomes randomized during each run. since the 'tar'
	# option accepts anything, if during randomization it gets in front of the actual
	# compression method the archive is using, the archive won't be opened properly anymore.
	#
	# this resulted in a very annoying heisenbug during the installation when ignore_zeros was
	# set to True. thanks to @yyjdelete for tracking it down: https://bugs.python.org/issue28449
	#
	# since ignore_zeros is pretty useful due to the use of multiple layers in the prebuilt images,
	# the workaround here is to monkeypatch the TarFile.OPEN_METH dictionary and replace it with
	# a dictionary whose order is preserved.

	tarfile.TarFile.OPEN_METH = OrderedDict()
	tarfile.TarFile.OPEN_METH['gz']  = 'gzopen'
	tarfile.TarFile.OPEN_METH['bz2'] = 'bz2open'
	tarfile.TarFile.OPEN_METH['xz']  = 'xzopen'
	tarfile.TarFile.OPEN_METH['tar'] = 'taropen'

	# extract rootfs from tarball

	fileobj = ProgressFileObject(fname)
	fileobj.current_extraction = 'Scanning archive...'

	try:
		ntfsea.init()
		path = os.path.join(homedirw, 'rootfs-temp')

		with tarfile.open(fileobj = fileobj, mode = 'r:*', dereference = True, ignore_zeros = True, errorlevel = 2) as tar:

			file = tar.next()

			if file is None:
				clear_progress()
				print('%s[!]%s Failed to extract archive: unable to determine archive type.' % (Fore.RED, Fore.RESET))
				exit(-1)

			while file is not None:
				try:

					# extract file

					file.name = file.name.lstrip('./')
					fileobj.current_extraction = file.name
					file.name = path + '/' + escape_ntfs_invalid(file.name)

					if file.issym() or file.islnk():

						# create symlink manually

						dirname = os.path.dirname(file.name)
						if not os.path.exists(dirname):
							os.makedirs(dirname, exist_ok=True)

						with open(file.name, 'w', encoding='utf-8') as link:
							link.write(file.linkname)

					elif file.isdev():

						# skip device files, such as /dev/*
						continue

					else:

						# extract file
						tar.extract(file, path)

					# apply lxattrb

					os.chmod(file.name, stat.S_IWRITE)

					attrb = lxattrb.fromtar(file).generate()
					ntfsea.writeattr(file.name, 'lxattrb', attrb)

				except Exception as err:
					clear_progress()
					print('%s[!]%s Failed to extract %s: %s' % (Fore.YELLOW, Fore.RESET, fileobj.current_extraction, err))
					pass

				finally:
					file = tar.next()

		# some archives don't seem to have the directories themselves as separate
		# entries, and this results in lxattrb not being applied to them, which will
		# lead to bash.exe returning Error: 0x80070002 or 0x8007001f

		dattrb = lxattrb(stmode.FDIR | 0o755).generate()
		fattrb = lxattrb(stmode.FREG | 0o755).generate()

		for root, subFolders, files in os.walk(path):

			# apply generic root:root 0755 to those without an attribute

			for folder in subFolders:
				folder = os.path.join(root, folder)

				if ntfsea.getattr(folder, 'lxattrb') is None:
					ntfsea.writeattr(folder, 'lxattrb', dattrb)

			for file in files:
				file = os.path.join(root, file)

				if ntfsea.getattr(file, 'lxattrb') is None:
					ntfsea.writeattr(file, 'lxattrb', fattrb)

	except Exception as err:
		clear_progress()
		print('%s[!]%s Failed to extract archive: %s' % (Fore.RED, Fore.RESET, err))
		exit(-1)

	finally:
		clear_progress()
		show_cursor()

# disable here for `path` and `SystemRoot` don't always have right case
if case_sensitive:
	try:
		ntfsea.disableposix()
	except Exception:
		pass

# read label of current distribution

clabel = get_label(os.path.join(basedir, 'rootfs'))

if not clabel:
	clabel = 'ubuntu_trusty'
	print('%s[!]%s No %s/.switch_label%s found, assuming current rootfs is %subuntu%s:%strusty%s.' % (Fore.RED, Fore.RESET, Fore.BLUE, Fore.RESET, Fore.YELLOW, Fore.RESET, Fore.YELLOW, Fore.RESET))

# do the switch

print('%s[*]%s Backing up current %srootfs%s to %srootfs_%s%s...' % (Fore.GREEN, Fore.RESET, Fore.BLUE, Fore.RESET, Fore.BLUE, clabel, Fore.RESET))

try:
	subprocess.check_output(['cmd', '/C', 'move', os.path.join(basedir, 'rootfs'), os.path.join(basedir, 'rootfs_' + clabel)])

except subprocess.CalledProcessError as err:
	print('%s[!]%s Failed to backup current %srootfs%s: %s' % (Fore.RED, Fore.RESET, Fore.BLUE, Fore.RESET, err))
	exit(-1)

print('%s[*]%s Switching to new %srootfs%s...' % (Fore.GREEN, Fore.RESET, Fore.BLUE, Fore.RESET))

time.sleep(1)

try:
	subprocess.check_output(['cmd', '/C', 'move', os.path.join(homedirw, 'rootfs-temp'), os.path.join(basedir, 'rootfs')])

except subprocess.CalledProcessError as err:
	print('%s[!]%s Failed to switch to new %srootfs%s: %s' % (Fore.RED, Fore.RESET, Fore.BLUE, Fore.RESET, err))
	print('%s[*]%s Rolling back to old %srootfs%s...' % (Fore.YELLOW, Fore.RESET, Fore.BLUE, Fore.RESET))

	try:
		subprocess.check_output(['cmd', '/C', 'move', os.path.join(basedir, 'rootfs_' + clabel), os.path.join(basedir, 'rootfs')])

	except subprocess.CalledProcessError as err:
		print('%s[!]%s Failed to roll back to old %srootfs%s: %s' % (Fore.RED, Fore.RESET, Fore.BLUE, Fore.RESET, err))
		print('%s[!]%s You are now the proud owner of one broken Linux subsystem! To fix it, run %slxrun /uninstall%s and %slxrun /install%s from the command prompt.' % (Fore.RED, Fore.RESET, Fore.GREEN, Fore.RESET, Fore.GREEN, Fore.RESET))

	exit(-1)

# save label

try:
	with open(os.path.join(basedir, 'rootfs', '.switch_label'), 'w') as f:
		f.write(label + '\n')

except OSError as err:
	print('%s[!]%s Failed to open file %s/.switch_label%s for writing: %s' % (Fore.RED, Fore.RESET, Fore.BLUE, Fore.RESET, err))

# append user entries to /etc/{passwd,shadow,group,gshadow}

print('%s[*]%s Writing entries of %sroot%s%s to %s/etc/{passwd,shadow,group,gshadow}%s...' % (Fore.GREEN, Fore.RESET, Fore.YELLOW, Fore.RESET, (' and %s%s%s' % (Fore.YELLOW, user, Fore.RESET) if not isroot else ''), Fore.BLUE, Fore.RESET))

if not isroot:
	try:
		with open(os.path.join(basedir, 'rootfs', 'etc', 'passwd'), 'a', newline='\n') as f:
			f.write(etcpasswduser + '\n')

	except OSError as err:
		print('%s[!]%s Failed to open file %s/etc/passwd%s for writing: %s' % (Fore.RED, Fore.RESET, Fore.BLUE, Fore.RESET, err))

if not isroot or etcshadowroot:
	try:
		shadows = []

		with open(os.path.join(basedir, 'rootfs', 'etc', 'shadow'), 'r+', newline='\n') as f:
			shadows = f.readlines()

			if etcshadowroot:
				for i in range(len(shadows)):
					if shadows[i].startswith('root:'):
						parts = shadows[i].split(':')
						parts[1] = etcshadowroot
						shadows[i] = ':'.join(parts)

			f.seek(0)
			f.writelines(shadows)

			if etcshadowuser:
				f.write(etcshadowuser + '\n')

	except OSError as err:
		print('%s[!]%s Failed to open file %s/etc/shadow%s for writing: %s' % (Fore.RED, Fore.RESET, Fore.BLUE, Fore.RESET, err))

if not isroot:
	try:
		with open(os.path.join(basedir, 'rootfs', 'etc', 'group'), 'a', newline='\n') as f:
			f.write(etcgroupuser + '\n')

	except OSError as err:
		print('%s[!]%s Failed to open file %s/etc/group%s for writing: %s' % (Fore.RED, Fore.RESET, Fore.BLUE, Fore.RESET, err))

	try:
		with open(os.path.join(basedir, 'rootfs', 'etc', 'gshadow'), 'a', newline='\n') as f:
			f.write(etcgshadowuser + '\n')

	except OSError as err:
		print('%s[!]%s Failed to open file %s/etc/gshadow%s for writing: %s' % (Fore.RED, Fore.RESET, Fore.BLUE, Fore.RESET, err))

# check if post-install hooks exist

havehooks = False

if runhooks:
	hooks = ['all', image, image + '_' + tag]

	for hook in hooks:
		hookfile = 'hook_postinstall_%s.sh' % hook

		if os.path.isfile(hookfile):
			havehooks = True
			break

# switch to root, if regular user and have hooks

if not isroot and havehooks:

	print('%s[*]%s Switching default user to %sroot%s...' % (Fore.GREEN, Fore.RESET, Fore.YELLOW, Fore.RESET))

	try:
		subprocess.check_output(['cmd', '/C', lxpath + '\\lxrun.exe', '/setdefaultuser', 'root'])

	except subprocess.CalledProcessError as err:
		print('%s[!]%s Failed to switch default user in WSL: %s' % (Fore.RED, Fore.RESET, err))
		exit(-1)

	try:
		subprocess.check_call(['cmd', '/C', lxpath + '\\bash.exe', '-c',
		                       'echo $HOME > /tmp/.wsl_usr.txt; echo $USER >> /tmp/.wsl_usr.txt'])
		out = os.path.join(basedir, 'rootfs/tmp/.wsl_usr.txt')

		if not os.path.isfile(out):
			print('%s[!]%s Failed to get home directory of default user in WSL: Output file %s%s%s not present.' % (Fore.RED, Fore.RESET, Fore.BLUE, out, Fore.RESET))
			exit(-1)

		with open(out) as f:
			homedir = f.readline().strip()
			homedirw = os.path.join(basedir, homedir.lstrip('/'))

			if len(homedir) == 0 or not os.path.isdir(homedirw):
				print('%s[!]%s Failed to get home directory of default user in WSL: Returned path %s%s%s is not valid.' % (Fore.RED, Fore.RESET, Fore.BLUE, homedirw, Fore.RESET))
				exit(-1)

			user2 = f.readline().strip()

			if user2 != 'root':
				print('%s[!]%s Failed to switch default user to %sroot%s.' % (Fore.RED, Fore.RESET, Fore.YELLOW, Fore.RESET))
				exit(-1)

		os.unlink(out)

	except subprocess.CalledProcessError as err:
		print('%s[!]%s Failed to get home directory of default user in WSL: %s' % (Fore.RED, Fore.RESET, err))
		exit(-1)

	# since we switched to root, switch back to regular user on exit

	def switch_user_back(user):
		print('%s[*]%s Switching default user back to %s%s%s...' % (Fore.GREEN, Fore.RESET, Fore.YELLOW, user, Fore.RESET))

		try:
			subprocess.check_output(['cmd', '/C', lxpath + '\\lxrun.exe', '/setdefaultuser', user])

		except subprocess.CalledProcessError as err:
			print('%s[!]%s Failed to switch default user in WSL: %s' % (Fore.RED, Fore.RESET, err))
			exit(-1)

	atexit.register(switch_user_back, user)

# run post-install hooks, if any

if havehooks:
	hooks = ['all', image, image + '_' + tag]

	for hook in hooks:
		hookfile = 'hook_postinstall_%s.sh' % hook

		if os.path.isfile(hookfile):
			print('%s[*]%s Running post-install hook %s%s%s...' % (Fore.GREEN, Fore.RESET, Fore.GREEN, hook, Fore.RESET))

			hookpath = os.path.join(homedirw, hookfile)

			try:
				subprocess.check_call(['cmd', '/C', lxpath + '\\bash.exe', '-c', 'echo -n > /root/%s && chmod +x /root/%s' % (hookfile, hookfile)])

				if not os.path.isfile(hookpath):
					print('%s[!]%s Failed to copy hook to WSL: File %s%s%s not present.' % (Fore.RED, Fore.RESET, Fore.BLUE, hookpath, Fore.RESET))
					continue

			except subprocess.CalledProcessError as err:
				print('%s[!]%s Failed to run hook in WSL: %s' % (Fore.RED, Fore.RESET, err))
				continue

			try:
				with open(hookfile) as s, open(hookpath, 'a', newline='\n') as d:
					d.write(s.read().replace('\r', ''))

			except OSError as err:
				print('%s[!]%s Failed to open hook: %s' % (Fore.RED, Fore.RESET, err))
				continue

			try:
				subprocess.check_call(['cmd', '/C', lxpath + '\\bash.exe', '-c', 'REGULARUSER="%s" WINVER="%d" /root/%s' % (user if not isroot else '', sys.getwindowsversion().build, hookfile)])

			except subprocess.CalledProcessError as err:
				print('%s[!]%s Failed to run hook in WSL: %s' % (Fore.RED, Fore.RESET, err))
				continue

			os.unlink(hookpath)

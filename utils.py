#!/usr/bin/env python3
# coding=utf-8
import io
import os
import sys
import glob
import time

# try to get colors, but don't make it a nuisance by requiring dependencies

has_filter = False
has_progress = False
last_progress = 0
conemu = False

if sys.platform == 'win32':
	try:
		from colorama import init
		init()
		has_filter = True
	except ImportError:
		pass

	import ctypes

	class ConsoleCursorInfo(ctypes.Structure):
		_fields_ = [("size", ctypes.c_int), ("visible", ctypes.c_byte)]

if not sys.platform == 'win32' or has_filter:
	class Fore:
		RED    = '\x1B[91m'
		GREEN  = '\x1B[92m'
		BLUE   = '\x1B[94m'
		YELLOW = '\x1B[93m'
		RESET  = '\x1B[39m'
else:
	class Fore:
		RED    = ''
		GREEN  = ''
		BLUE   = ''
		YELLOW = ''
		RESET  = ''


# parse image[:tag] | archive argument

def parse_image_arg(argv, can_be_file = False):
	"""
	Parses the image[:tag] argument passed to the script. When can_be_file is True,
	the argument can also be a filename, _and_ if it is not, the generated image:tag
	should have a corresponding rootfs archive available.

	:param argv: Passed argument.
	:param can_be_file: Whether argument can be a file and image:tag should also resolve to a file.

	:return: Name of the image, tag, name of the file, label.
	"""

	exts  = ['.tar', '.sfs', '.squashfs']
	argvl = argv.lower()
	image = argv
	tag   = 'latest'
	fname = ''
	label = ''

	if not can_be_file or all(ext not in argvl for ext in exts):

		# handle image:tag

		if ':' in image:
			idx   = image.find(':')
			tag   = image[idx + 1:]
			image = image[:idx]

		if can_be_file:
			fname = 'rootfs_%s_%s.tar*' % (image.replace('/', '_'), tag)
			names = glob.glob(fname)

			if len(names) > 0:
				fname = names[0]
			else:
				print('%s[!]%s No files found matching %s%s%s.' % (Fore.RED, Fore.RESET, Fore.BLUE, fname, Fore.RESET))
				exit(-1)

		else:
			fname = 'rootfs_%s_%s' % (image.replace('/', '_'), tag)

		label = '%s_%s' % (image.replace('/', '_'), tag)

	else:

		# handle file name

		fname = argv

		if not os.path.isfile(fname):
			print('%s[!]%s %s%s%s is not an existing file.' % (Fore.RED, Fore.RESET, Fore.BLUE, fname, Fore.RESET))
			exit(-1)

		idx = -1
		basename = os.path.basename(argvl)

		for ext in exts:
			idx = basename.find(ext)

			if idx != -1:
				break

		label = basename[:idx]

		if label.startswith('rootfs_'):
			label = label[len('rootfs_'):]

		if label.find('_') == -1:
			label += '_' + tag

	return image, tag, fname, label


# sanity check WSL installation

def probe_wsl(silent = False):
	"""
	Checks whether the WSL is installed and not running.

	:type silent: Whether to print an error message or just return an empty string on failure.

	:return: Paths to the WSL directory and lxrun/bash executables.
	"""

	basedir = os.path.join(os.getenv('LocalAppData'), 'lxss')

	if not os.path.isdir(basedir):
		if silent:
			return None, None

		print('%s[!]%s The Linux subsystem is not installed. Please go through the standard installation procedure first.' % (Fore.RED, Fore.RESET))
		exit(-1)

	if os.path.exists(os.path.join(basedir, 'temp')):
		if silent:
			return None, None

		print('%s[!]%s The Linux subsystem is currently running. Please kill all instances before continuing.' % (Fore.RED, Fore.RESET))
		exit(-1)

	lxpath  = ''
	lxpaths = [os.path.join(os.getenv('SystemRoot'), 'sysnative'), os.path.join(os.getenv('SystemRoot'), 'System32')]

	for path in lxpaths:
		if os.path.exists(os.path.join(path, 'lxrun.exe')):
			lxpath = path
			break

	if not lxpath and not silent:
		print('%s[!]%s Unable to find %slxrun.exe%s in the expected locations.' % (Fore.RED, Fore.RESET, Fore.BLUE, Fore.RESET))
		exit(-1)

	return basedir, lxpath


# get label of rootfs

def get_label(path):
	"""
	Gets the label for the specified rootfs. If the .switch_label file is not present,
	but the OS was identified, the file will be created for future use.

	:param path: Path to the rootfs.

	:return: Label of the rootfs.
	"""

	# see if .switch_label exists

	if os.path.isfile(os.path.join(path, '.switch_label')):
		try:
			with open(os.path.join(path, '.switch_label')) as f:
				label = f.readline().strip()

				if len(label) > 0:
					return label

		except OSError:
			pass

	# check if the directory name has any stuff appended to it

	dirname = os.path.basename(path)

	if dirname.startswith('rootfs_'):
		label = dirname[len('rootfs_'):]

		if len(label) > 0:

			# save label for next occasion

			try:
				with open(os.path.join(path, '.switch_label'), 'w') as f:
					f.write(label + '\n')
			except OSError:
				pass

			return label

	# see if any *release files exist in /etc/

	rlsfiles = glob.glob(os.path.join(path, 'etc', '*release')) + glob.glob(os.path.join(path, 'usr', 'lib', 'os-release*'))

	if len(rlsfiles) > 0:
		rlslines = []

		for file in rlsfiles:
			try:
				with open(file) as f:
					rlslines += f.readlines()
			except OSError:
				pass

		name = ['', '', '']  # ID || DISTRIB_ID || NAME
		vers = ['', '', '']  # DISTRIB_CODENAME || DISTRIB_RELEASE || VERSION_ID

		for line in rlslines:
			kv = line.split('=', 1)

			if len(kv) < 2:
				continue

			key = kv[0].strip().strip('"\'').lower()
			val = kv[1].strip().strip('"\'').lower()

			if len(val) == 0:
				continue

			if key == 'id':
				name[0] = val
			elif key == 'distrib_id':
				name[1] = val
			elif key == 'name':
				name[2] = val

			if key == 'distrib_codename':
				vers[0] = val
			elif key == 'distrib_release':
				vers[1] = val
			elif key == 'version_id':
				vers[2] = val

		name = list(filter(None, name))
		vers = list(filter(None, vers))

		if len(name) > 0:
			label = name[0] + ('_' + vers[0] if len(vers) > 0 else '')

			# save label for next occasion

			try:
				with open(os.path.join(path, '.switch_label'), 'w') as f:
					f.write(label + '\n')
			except OSError:
				pass

			return label

	# oh well

	return ''


# toggle cursor visibility in the terminal

def show_cursor():
	"""
	Turns the cursor back on in the terminal.
	"""

	if not sys.platform == 'win32':
		sys.stdout.write('\033[?25h')

	else:
		ci = ConsoleCursorInfo()
		handle = ctypes.windll.kernel32.GetStdHandle(-11)
		ctypes.windll.kernel32.GetConsoleCursorInfo(handle, ctypes.byref(ci))
		ci.visible = True
		ctypes.windll.kernel32.SetConsoleCursorInfo(handle, ctypes.byref(ci))


def hide_cursor():
	"""
	Turns the cursor off in the terminal.
	"""

	global conemu

	if not sys.platform == 'win32':
		sys.stdout.write('\033[?25l')
		conemu = False

	else:
		ci = ConsoleCursorInfo()
		handle = ctypes.windll.kernel32.GetStdHandle(-11)
		ctypes.windll.kernel32.GetConsoleCursorInfo(handle, ctypes.byref(ci))
		ci.visible = False
		ctypes.windll.kernel32.SetConsoleCursorInfo(handle, ctypes.byref(ci))
		conemu = os.environ.get('ConEmuANSI') == 'ON'


# some characters are forbidden in NTFS, but are not in ext4. the most popular of these characters
# seems to be the colon character. LXSS solves this issue by escaping the character on NTFS.
# while this seems like a dumb implementation, it will be called a lot of times inside the
# decompression loop, so it has to be fast: http://stackoverflow.com/a/27086669/156626

def escape_ntfs_invalid(name):
	"""
	Escapes characters which are forbidden in NTFS, but are not in ext4.

	:param name: Path potentially containing forbidden NTFS characters.

	:return: Path with forbidden NTFS characters escaped.
	"""
	return name.replace('*', '#002A').replace('|', '#007C').replace(':', '#003A').replace('>', '#003E').replace('<', '#003C').replace('?', '#003F').replace('"', '#0022')


# stream copier with progress bar

def chunked_copy(name, source, dest):
	"""
	Copies one stream into another, with progress bar.

	:param name: Name of the file to display.
	:param source: Source stream.
	:param dest: Destination stream.

	:return: Number of bytes copied.
	"""

	global conemu

	size = int(source.info()['Content-Length'].strip())
	recv = 0

	if len(name) > 23:
		name = name[0:20] + '...'

	hide_cursor()

	while True:
		chunk = source.read(8192)
		recv += len(chunk)

		if not chunk:
			break

		dest.write(chunk)

		draw_progress(recv, size, name)

	show_cursor()

	return recv


# FileIO wrapper with progress bar

class ProgressFileObject(io.FileIO):
	def __init__(self, path, *args, **kwargs):
		self._total_size = os.path.getsize(path)
		self.current_extraction = ''
		io.FileIO.__init__(self, path, *args, **kwargs)

		hide_cursor()

	def read(self, length):
		"""
		Read at most size bytes, returned as bytes.

		Only makes one system call, so less data may be returned than requested.
		In non-blocking mode, returns None if no data is available.
		Return an empty bytes object at EOF.
		"""

		draw_progress(self.tell(), self._total_size, self.current_extraction)

		return io.FileIO.read(self, length)

	def __del__(self):
		show_cursor()


# standalone function to draw an interactive progressbar

def draw_progress(recv, size, name):
	"""
	Draws an interactive progressbar based on the specified information.

	:param recv: Number of bytes received.
	:param size: Total size of the file.
	:param name: Name of the file to display.
	"""

	global conemu, has_progress, last_progress

	if recv > size:
		recv = size

	if recv == size:
		clear_progress()
		return

	if time.time() - last_progress < 0.05:
		return

	has_progress  = True
	last_progress = time.time()

	if len(name) > 23:
		name = name[0:20] + '...'
	else:
		name = name.ljust(23, ' ')

	pct = round(recv / size * 100, 2)
	bar = int(50 * recv / size)
	sys.stdout.write('\r    %s [%s>%s] %0.2f%%' % (name, '=' * bar, ' ' * (50 - bar), pct))

	if conemu:
		sys.stdout.write('\033]9;4;1;%0.0f\033\\\033[39m' % pct)

	sys.stdout.flush()


def clear_progress():
	"""
	Clears the progress bar.
	"""

	global conemu, has_progress

	if not has_progress:
		return

	has_progress = False

	sys.stdout.write('\r%s\r' % (' ' * (66 + 23)))

	if conemu:
		sys.stdout.write('\033]9;4;0\033\\\033[39m')

	sys.stdout.flush()

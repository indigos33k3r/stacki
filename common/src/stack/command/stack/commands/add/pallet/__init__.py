# @copyright@
# Copyright (c) 2006 - 2019 Teradata
# All rights reserved. Stacki(r) v5.x stacki.com
# https://github.com/Teradata/stacki/blob/master/LICENSE.txt
# @copyright@
#
# @rocks@
# Copyright (c) 2000 - 2010 The Regents of the University of California
# All rights reserved. Rocks(r) v5.4 www.rocksclusters.org
# https://github.com/Teradata/stacki/blob/master/LICENSE-ROCKS.txt
# @rocks@

import os
import sys
import tempfile
import pathlib
import subprocess
import stack.file
from stack.util import _exec
import stack.commands
from stack.download import fetch, FetchError
from stack.exception import CommandError, ParamRequired, UsageError

class command(stack.commands.add.command):
	pass


class Command(command):
	"""
	Add pallet ISO images to this machine's pallet directory. This command
	copies all files in the ISOs to the local machine. The default location
	is a directory under /export/stack/pallets.

	<arg optional='1' type='string' name='pallet' repeat='1'>
	A list of pallet ISO images to add to the local machine. If no list is
	supplied, then if a pallet is mounted on /mnt/cdrom, it will be copied
	to the local machine. If the pallet is hosted on the internet, it will
	be downloaded and stored on the local machine.
	</arg>

	<param type='string' name='username'>
	If the pallet's download server requires authentication.
	</param>

	<param type='string' name='password'>
	If the pallet's download server requires authentication.
	</param>
		
	<param type='bool' name='clean'>
	If set, then remove all files from any existing pallets of the same
	name, version, and architecture before copying the contents of the
	pallets onto the local disk.  This parameter should not be set
	when adding multi-CD pallets such as the OS pallet, but should be set
	when adding single pallet CDs such as the Grid pallet.
	</param>

	<param type='string' name='dir'>
	The base directory to copy the pallet to.
	The default is: /export/stack/pallets.
	</param>

	<param type='string' name='updatedb'>
	Add the pallet info to the cluster database.
	The default is: true.
	</param>
	
	<example cmd='add pallet clean=1 kernel*iso'>
	Adds the Kernel pallet to local pallet directory.  Before the pallet is
	added the old Kernel pallet packages are removed from the pallet
	directory.
	</example>
	
	<example cmd='add pallet kernel*iso pvfs2*iso ganglia*iso'>
	Added the Kernel, PVFS, and Ganglia pallets to the local pallet
	directory.
	</example>

	<related>remove pallet</related>
	<related>enable pallet</related>
	<related>disable pallet</related>
	<related>list pallet</related>
	<related>create pallet</related>
	"""

	def copy(self, clean, prefix, updatedb, URL):
		"""Copy all the pallets from the CD to Disk"""

		# Populate the info hash. This hash contains pallet
		# information about all the pallets present on disc.

		p = subprocess.run(['find', '%s' % self.mountPoint, '-type', 'f', '-name', 'roll-*.xml'],
				   stdout=subprocess.PIPE)
		dict = {}
		for filename in p.stdout.decode().split('\n'):
			if filename:
				roll = stack.file.RollInfoFile(filename.strip())
				dict[roll.getRollName()] = roll

		if len(dict) == 0:
			
			# If the roll_info hash is empty, that means there are
			# no stacki recognizable rolls on the Disc. This mean
			# it may just be a normal OS CD like CentOS, RHEL,
			# Ubuntu, or SuSE. In any case it's a
			# foreign CD, and should be treated as such.
			#
			self.loadImplementation()
			impl_found = False
			for i in self.impl_list:
				if hasattr(self.impl_list[i], 'check_impl'):
					if self.impl_list[i].check_impl():
						impl_found = True
						res = self.runImplementation(i, (clean, prefix))
						break

			if not impl_found:
				raise CommandError(self, 'unknown pallet on %s' % self.mountPoint)

			if res:
				if updatedb:
					self.insert(res[0], res[1], res[2], res[3], res[4], URL)
				if self.dryrun:
					self.addOutput(res[0], [res[1], res[2], res[3], res[4], URL])

		#
		# Keep going even if a foreign pallet.  Safe to loop over an
		# empty list.
		#
		# For all pallets present, copy into the pallets directory.
		
		for key, info in dict.items():
			self.runImplementation('native_%s' % info.getRollOS(),
					       (clean, prefix, info))
			name	= info.getRollName()
			version	= info.getRollVersion()
			release	= info.getRollRelease()
			arch	= info.getRollArch()
			osname	= info.getRollOS()
			if updatedb:
				self.insert(name, version, release, arch, osname, URL)
			if self.dryrun:
				self.addOutput(name, [version, release, arch, osname, URL])


	def insert(self, name, version, release, arch, OS, URL):
		"""
		Insert the pallet information into the database if
		not already present.
		"""

		if self.db.count(
			'(ID) from rolls where name=%s and version=%s and rel=%s and arch=%s and os=%s',
			(name, version, release, arch, OS)
		) == 0:
			self.db.execute("""
				insert into rolls(name, version, rel, arch, os, URL)
				values (%s, %s, %s, %s, %s, %s)
				""", (name, version, release, arch, OS, URL)
			)

	def mount(self, iso_name):
		# ensure iso isn't already mounted
		# this appears to be a sles12 quirk?  `mount some.iso /mntpt1; mount some.iso /mntpt2` fails
		for line in _exec('mount').stdout.splitlines():
			line = line.split()
			if iso_name != line[0]:
				continue

			msg = f'"{iso_name}" is already mounted at {line[2]}: Attempting to unmount.\n')
			stack.commands.Log(msg)
			try_umount = _exec(f'umount {other_mountpoint}')
			if try_umount.returncode != 0:
				raise CommandError(self, f'{msg}Failed to unmount:\n{try_umount.stderr}')
			# safe to stop looping...
			break

		# if we get here, the iso was unmounted or never mounted in the first place
		tempdir = tempfile.TemporaryDirectory()
		mount = _exec(f'mount {tempdir.name}', shlexsplit=True)
		if mount.returncode != 0:
			raise CommandError(self, 'Pallet could not be added - unable to mount {iso_name}.\n{mount.stderr}')

		return tempdir.name

	def run(self, params, args):
		(clean, stacki_pallet_dir, updatedb, dryrun, username, password) = self.fillParams([
			('clean', False),
			('dir', '/export/stack/pallets'),
			('updatedb', True),
			('dryrun', False),
			('username', None),
			('password', None),
		])

		# need to provide either both or none
		if not all((username, password)):
			raise UsageError(self, 'must supply a password along with the username')

		clean = self.str2bool(clean)
		updatedb = self.str2bool(updatedb)
		self.dryrun = self.str2bool(dryrun)
		if self.dryrun:
			updatedb = False
			self.out = sys.stderr
		else:
			self.out = sys.stdout

		temp_mount_dir = tempfile.TemporaryDirectory()
		self.mountPoint = temp_mount_dir.name

		# Get a list of all the iso files mentioned in
		# the command line. Make sure we get the complete 
		# path for each file.

		isolist = []
		network_pallets = []
		disk_pallets    = []
		for arg in args:
			if arg.startswith(('http', 'ftp')) and arg.endswith('.iso'):
				isolist.append(arg)
				continue
			elif arg.startswith(('http', 'ftp')):
				network_pallets.append(arg)
				continue

			arg = os.path.join(os.getcwd(), arg)
			if os.path.exists(arg) and arg.endswith('.iso'):
				isolist.append(arg)
			elif os.path.isdir(arg):
				disk_pallets.append(arg)
			else:
				msg = "Cannot find %s or %s is not an ISO image"
				raise CommandError(self, msg % (arg, arg))

		if self.dryrun:
			self.beginOutput()

		# CASE 1: no args were specified - check if a pallet is mounted at /mnt/cdrom
		if not any((isolist, network_pallets, disk_pallets)):

			self.mountPoint = '/mnt/cdrom'
			result = _exec(f'mount | grep {self.mountPoint}', shell=True)
			if result.returncode == 0:
				self.copy(clean, stacki_pallet_dir, updatedb, self.mountPoint)
			else:
				raise CommandError(self, 'no pallets provided and /mnt/cdrom is unmounted')

		# CASE 2: some of the specified args are .iso files, either local or remote
		for iso in isolist:
			# XXX these become 'disk_pallets' ????
			local_file = iso
			if iso.startswith(('http', 'ftp')):
				tempdir = tempfile.TemporaryDirectory()

				try:
					# passing True will display a % progress indicator in stdout
					local_file = fetch(iso, username, password, True, f'{tempdir.name}/{pathlib.Path(iso).name}')
				except FetchError as e:
					raise CommandError(self, e)

			cwd = os.getcwd()
			mount_point = mount(iso)
			self.copy(clean, stacki_pallet_dir, updatedb, iso)
			os.chdir(cwd)
			result = _exec(f'umount {self.mountPoint}', shlexsplit=True)
			if iso.startswith(('http', 'ftp')):
				print('cleaning up temporary files ...')
				os.unlink(local_file)

		# CASE 3: some of the specified args are remote paths to already exploded pallet directories
		for pallet in network_pallets:
			self.runImplementation('network_pallet', (clean, stacki_pallet_dir, pallet, updatedb))

		# CASE 4: some of the specified args are local paths to already exploded pallet directories
		for pallet in disk_pallets:
			self.runImplementation('disk_pallet', (clean, stacki_pallet_dir, pallet, updatedb))

		if self.dryrun:
			self.endOutput(header=['name', 'version', 'release', 'arch', 'os'], trimOwner=False)

		# Clear the old packages
		_exec('systemctl start ludicrous-cleaner'.split())

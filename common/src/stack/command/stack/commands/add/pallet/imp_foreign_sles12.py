# @copyright@
# Copyright (c) 2006 - 2019 Teradata
# All rights reserved. Stacki(r) v5.x stacki.com
# https://github.com/Teradata/stacki/blob/master/LICENSE.txt
# @copyright@
#

import os
import stack.commands
from stack.exception import CommandError
from stack.util import _exec


class Implementation(stack.commands.Implementation):	
	"""
	Copy a SLES/CaaSP ISO to the frontend.
	"""

	def check_impl(self):
		# Check the DISTRO line in the content file
		# This should be of the format
		# DISTRO	   cpe:/o:suse:sles:12:sp2,SUSE Linux Enterprise Server 12 SP2
		#
		# or:
		#
		# DISTRO	cpe:/o:suse:caasp:1.0,SUSE Container as a Service Platform 1.0

		self.name = None
		self.vers = None
		self.release = None
		self.arch = 'x86_64'

		found_distro = False
		if os.path.exists(f'{self.owner.mountPoint}/content'):
			file = open(f'{self.owner.mountPoint}/content', 'r')

			for line in file.readlines():
				l = line.split(None, 1)
				if len(l) > 1:
					key = l[0].strip()
					value = l[1].strip()

					if key == 'DISTRO':
						a = value.split(',')
						v = a[0].split(':')
						
						if v[3] == 'sles':
							self.name = 'SLES'
						elif v[3] == 'sle-sdk':
							self.name = v[3].upper()
						elif v[3] == 'ses':
							self.name = 'SUSE-Enterprise-Storage'

						if self.name:
							self.vers = v[4]
							if len(v) > 5:
								self.release = v[5]
							found_distro = True
						else:
							return False


			file.close()
		if not self.release:
			self.release = stack.release
		if found_distro:
			return True
		else:
			return False


	def run(self, args):
		clean, prefix = args
		# TODO fix this when we decide on attributes vs arguments
		name, version, release, arch = self.name, self.vers, self.release, self.arch

		if not name:
			raise CommandError(self, 'unknown SLES on media')
		if not version:
			raise CommandError(self, 'unknown SLES version on media')

		OS = 'sles'

		pallet_dir = self.owner.actually_copy(prefix, name, version, release, OS, arch, clean)
		self.owner.write_pallet_xml(prefix, name, version, release, OS, arch)

		# Copy pallet patches into the respective pallet directory
		# TODO this is one piece of the "pallet post-add hooks"

		patch_dir = f'/opt/stack/{name}-pallet-patches/{version}/{release}'
		if os.path.exists(patch_dir):
			self.owner.out.write(f'Patching {name} pallet\n')
			if not self.owner.dryrun:
				results = _exec('rsync --archive {patch_dir}/ {pallet_dir}/', shlexsplit=True)
				if results.returncode != 0:
					raise CommandError(self, 'patch failed:\n{results.stderr}')

		return name, version, release, arch, OS, pallet_dir

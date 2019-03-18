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
import stack
import stack.commands


class Implementation(stack.commands.Implementation):	
	"""
	This supports RHEL, CentOS, Oracle "Enterprise" Linux, and Scientific Linux.
	"""

	def check_impl(self):
		""" redhat distro's have a .treeinfo file """
		self.treeinfo = os.path.join(self.owner.mountPoint, '.treeinfo')
		return os.path.exists(self.treeinfo)

	def run(self, args):
		clean, prefix = args

		name = "BaseOS"
		version = stack.version
		release = stack.release
		OS = 'redhat'
		arch = 'x86_64'

		with open(self.treeinfo, 'r') as fi:
			for line in fi.readlines():
				kv = line.split('=')
				if len(kv) != 2:
					continue

				key, value = kv[0].strip(), kv[1].strip()

				if key == 'family':
					if value == 'Red Hat Enterprise Linux':
						name = 'RHEL'
					elif value.startswith('CentOS'):
						name = 'CentOS'
					elif value.startswith('Oracle'):
						name = 'OLE'
					elif value.startswith('Scientific'):
						name = 'SL'
				elif key == 'version':
					version = value
				elif key == 'arch':
					arch = value

		pallet_dir = self.owner.actually_copy(prefix, name, version, release, OS, arch, clean)
		self.owner.write_pallet_xml(prefix, name, version, release, OS, arch)

		return name, version, release, arch, OS, pallet_dir

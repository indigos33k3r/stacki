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
import stack.commands
from stack.exception import CommandError
from stack.util import _exec


class Implementation(stack.commands.Implementation):
	"""
	Copy a native Stacki roll.
	"""
	
	def run(self, args):
		clean, prefix, info = args

		name = info.getRollName()
		version = info.getRollVersion()
		arch = info.getRollArch()
		release = info.getRollRelease()
		OS = info.getRollOS()

		pallet_dir = self.owner.actually_copy(prefix, name, version, release, OS, arch, clean)

		# go back to the top of the pallet
		# TODO fix this -- probably should just be a command-wide last command
		roll_dir = os.path.join(prefix, name)
		os.chdir(os.path.join(self.owner.mountPoint, name))

		# after copying the roll, make sure everyone (apache included)
		# can traverse the directories
		if not self.owner.dryrun:
			result = _exec(r'find {0} -type d -exec chmod a+rx {} \;'.format(roll_dir))
			if result.returncode != 0:
				msg = 'Error while attempting to give apache read access to the pallets\n'
				raise CommandError(self, msg + result.stderr)

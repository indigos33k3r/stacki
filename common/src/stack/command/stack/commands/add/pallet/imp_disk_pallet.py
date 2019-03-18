#
# @copyright@
# Copyright (c) 2006 - 2019 Teradata
# All rights reserved. Stacki(r) v5.x stacki.com
# https://github.com/Teradata/stacki/blob/master/LICENSE.txt
# @copyright@
#

import pathlib
import stack.commands
from stack.exception import CommandError


class Implementation(stack.commands.Implementation):
	"""
	Add a pallet from a directory on disk.
	Really a re-add since the files are not copied.
	"""

	def run(self, args):
		clean, prefix, loc, updatedb = args

		# get just the final portion, throw the rest away
		try:
			*_, name, version, release, osname, arch = pathlib.Path(loc).parts
		except ValueError:
			raise CommandError(self, f'Unable to parse pallet directory structure: {loc}')

		if self.owner.dryrun:
			self.owner.addOutput(name, [version, release, arch, osname, loc])
		if updatedb:
			self.owner.insert(name, version, release, arch, osname, loc)

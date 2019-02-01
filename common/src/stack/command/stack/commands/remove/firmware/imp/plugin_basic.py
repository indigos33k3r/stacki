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

from pymysql import IntegrityError
import stack.commands
from stack.exception import ArgRequired, CommandError

class Plugin(stack.commands.Plugin):
	"""Attempts to remove implementations."""

	def provides(self):
		return "basic"

	def run(self, args):
		# Require implementation names
		if not args:
			raise ArgRequired(cmd = self.owner, arg = "imps")
		# remove any duplicates
		args = self.owner.remove_duplicates(args = args)
		# The imps must exist
		self.owner.validate_imps_exist(imps = args)

		# remove the implementations
		try:
			self.owner.db.execute("DELETE FROM firmware_imp WHERE name IN %s", (args,))
		except IntegrityError:
			raise CommandError(
				cmd = self.owner,
				msg = (
					f"Failed to remove all implementations because some are still in use."
					f" Please run 'stack list firmware model expanded=true' to list the"
					f" models still using the implementation and 'stack remove firmware model' to remove them."
				)
			)

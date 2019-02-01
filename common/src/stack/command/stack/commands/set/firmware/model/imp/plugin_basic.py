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

import stack.commands
from stack.exception import ArgRequired, ParamRequired, ParamError

class Plugin(stack.commands.Plugin):
	"""Attempts to associate an implementation with makes."""

	def provides(self):
		return 'basic'

	def run(self, args):
		params, models = args
		imp, make, = self.owner.fillParams(
			names = [
				('imp', ''),
				('make', ''),
			],
			params = params
		)
		# Require model names
		if not models:
			raise ArgRequired(cmd = self.owner, arg = 'models')

		# The make is required
		if not make:
			raise ParamRequired(cmd = self.owner, param = 'make')
		# The make must exist
		if not self.owner.make_exists(make = make):
			raise ParamError(
				cmd = self.owner,
				param = 'make',
				msg = f'The make {make} does not exist.'
			)

		models = self.owner.remove_duplicates(args = models)
		# The models must exist
		self.owner.validate_models_exist(make = make, models = models)
		# A implementation is required
		if not imp:
			raise ParamRequired(cmd = self.owner, param = 'imp')
		# The implementation must exist
		if not self.owner.imp_exists(imp = imp):
			raise ParamError(
				cmd = self.owner,
				param = 'imp',
				msg = f'The implementation {imp} does not exist.'
			)

		# get the implementation ID
		imp_id = self.owner.get_imp_id(imp = imp)
		# associate the firmware versions with the imp
		self.owner.db.execute(
			"""
			UPDATE firmware_model
				INNER JOIN firmware_make
					ON firmware_model.make_id = firmware_make.id
			SET firmware_model.imp_id=%s
			WHERE firmware_make.name = %s AND firmware_model.name IN %s
			""",
			(imp_id, make, args)
		)

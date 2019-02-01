# @copyright@
# Copyright (c) 2006 - 2018 Teradata
# All rights reserved. Stacki(r) v5.x stacki.com
# https://github.com/Teradata/stacki/blob/master/LICENSE.txt
# @copyright@
#
# @rocks@
# Copyright (c) 2000 - 2010 The Regents of the University of California
# All rights reserved. Rocks(r) v5.4 www.rocksclusters.org
# https://github.com/Teradata/stacki/blob/master/LICENSE-ROCKS.txt
# @rocks@

from contextlib import ExitStack
from pathlib import Path
import inspect
import stack.commands
import stack.commands.list.host.firmware
import stack.commands.sync.host.firmware
from stack.exception import CommandError, ArgRequired, ArgUnique, ArgError, ParamRequired, ParamError

class Plugin(stack.commands.Plugin):
	"""Attempts to add an implementation to the database and associate it appropriately."""

	def provides(self):
		return 'basic'

	def validate_arguments(self, args, make, models):
		"""Validates all arguments are specified correctly and raises an exception if they are not."""
		# Require a implementation name
		if not args:
			raise ArgRequired(cmd = self.owner, arg = 'name')
		# Should only be one
		if len(args) != 1:
			raise ArgUnique(cmd = self.owner, arg = 'name')

		imp = args[0]
		# Should not already exist
		if self.owner.imp_exists(imp = imp):
			raise ArgError(
				cmd = self.owner,
				arg = 'name',
				msg = f'An implementation named {imp} already exists in the database.',
			)
		# Should exist on disk
		list_firmware_imp = Path(inspect.getsourcefile(stack.commands.list.host.firmware)).parent.resolve() / f'imp_{imp}.py'
		sync_firmware_imp = Path(inspect.getsourcefile(stack.commands.sync.host.firmware)).parent.resolve() / f'imp_{imp}.py'
		if not list_firmware_imp.exists() or not sync_firmware_imp.exists():
			raise ArgError(
				cmd = self.owner,
				arg = 'name',
				msg = (
					f'Could not find an implementation named imp_{imp}.py. Please ensure an'
					f' implementation file is placed into each of the following locations:\n'
					f'{list_firmware_imp}\n{sync_firmware_imp}'
				)
			)

		# Process the make if present.
		if make:
			# models now required
			if not models:
				raise ParamRequired(cmd = self.owner, param = 'models')
			# The make must exist
			if not self.owner.make_exists(make = make):
				raise ParamError(
					cmd = self.owner,
					param = 'make',
					msg = f'The make {make} does not exist.'
				)
		# Process the models if present
		if models:
			# A make is now required
			if not make:
				raise ParamRequired(cmd = self.owner, param = 'make')

			# process a comma separated list of models
			models = [model.strip() for model in models.split(",") if model.strip()]
			# The models must exist
			try:
				self.owner.validate_models_exist(make = make, models = models)
			except CommandError as exception:
				raise ParamError(
					cmd = self.owner,
					param = 'models',
					msg = f'{exception}'
				)

		return imp, make, models

	def run(self, args):
		params, args = args
		make, models, = self.owner.fillParams(
			names = [
				('make', ''),
				('models', ''),
			],
			params = params
		)

		# validate all arguments before use
		imp, make, models, = self.validate_arguments(
			args = args,
			make = make,
			models = models,
		)

		with ExitStack() as cleanup:
			# add the imp
			self.owner.db.execute(
				'''
				INSERT INTO firmware_imp (
					name
				)
				VALUES (%s)
				''',
				args
			)
			cleanup.callback(self.owner.call, command = 'remove.firmware.imp', args = [imp])

			# If the make and model are specified associate the imp with the make + model
			if make and models:
				self.owner.call(
					command = 'set.firmware.model.imp',
					args = [
						*models,
						f'make={make}',
						f'imp={imp}',
					]
				)
			# else no association, just put it in the database.

			# everything worked, dismiss cleanup
			cleanup.pop_all()

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

import stack.commands
from stack.exception import ArgError, ParamError, ParamRequired, CommandError
from pathlib import Path

class Plugin(stack.commands.Plugin):
	"""Attempts to remove all provided firmware versions for the given make and model from the database and the file system."""

	def provides(self):
		return 'basic'

	def run(self, args):
		params, versions = args
		make, model = self.owner.fillParams(
			names = [('make', ''), ('model', '')],
			params = params
		)

		# process make if present
		if make:
			# ensure the make exists
			if not self.owner.make_exists(make = make):
				raise ParamError(
					cmd = self.owner,
					param = 'make',
					msg = f"The make {make} doesn't exist."
				)
		# process model if present
		if model:
			# make is now required
			if not make:
				raise ParamRequired(cmd = self.owner, param = 'make')
			# ensure the model exists
			if not self.owner.model_exists(make = make, model = model):
				raise ParamError(
					cmd = self.owner,
					param = 'model',
					msg = f"The model {model} doesn't exist for make {make}."
				)
		# Process versions if present
		if versions:
			# make and model are now required
			if not make:
				raise ParamRequired(cmd = self.owner, param = 'make')
			if not model:
				raise ParamRequired(cmd = self.owner, param = 'model')
			# get rid of any duplicate names
			versions = self.owner.remove_duplicates(args = versions)
			# ensure the versions exist
			try:
				self.owner.validate_firmwares_exist(make = make, model = model, versions = versions)
			except CommandError as exception:
				raise ArgError(
					cmd = self.owner,
					arg = 'version',
					msg = exception.message()
				)

		# If versions are specified, get the specific versions to remove
		if versions:
			firmware_to_remove = [
				(row[0], row[1]) for row in self.owner.db.select(
					'''
					firmware.id, firmware.file
					FROM firmware
						INNER JOIN firmware_model
							ON firmware.model_id=firmware_model.id
						INNER JOIN firmware_make
							ON firmware_model.make_id=firmware_make.id
					WHERE firmware.version IN %s AND firmware_make.name=%s AND firmware_model.name=%s
					''',
					(versions, make, model)
				)
			]
		# Else if make and model are specified, remove all firmwares for that make and model
		elif make and model:
			firmware_to_remove = [
				(row[0], row[1]) for row in self.owner.db.select(
					'''
					firmware.id, firmware.file
					FROM firmware
						INNER JOIN firmware_model
							ON firmware.model_id=firmware_model.id
						INNER JOIN firmware_make
							ON firmware_model.make_id=firmware_make.id
					WHERE firmware_make.name=%s AND firmware_model.name=%s
					''',
					(make, model)
				)
			]
		# Else if make is specified, remove all firmwares for that make
		elif make:
			firmware_to_remove = [
				(row[0], row[1]) for row in self.owner.db.select(
					'''
					firmware.id, firmware.file
					FROM firmware
						INNER JOIN firmware_model
							ON firmware.model_id=firmware_model.id
						INNER JOIN firmware_make
							ON firmware_model.make_id=firmware_make.id
					WHERE firmware_make.name=%s
					''',
					(make,)
				)
			]
		# otherwise remove all firmware
		else:
			firmware_to_remove = [
				(row[0], row[1]) for row in self.owner.db.select('firmware.id, firmware.file FROM firmware')
			]

		# remove the file and then the db entry for each firmware to remove
		for firmware_id, file_path in firmware_to_remove:
			Path(file_path).resolve(strict = True).unlink()
			self.owner.db.execute('DELETE FROM firmware WHERE id=%s', firmware_id)

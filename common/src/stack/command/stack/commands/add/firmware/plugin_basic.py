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
from stack.exception import ArgRequired, ArgUnique, ArgError, ParamRequired, ParamError
import stack.firmware
from pathlib import Path
from contextlib import ExitStack
import re

class Plugin(stack.commands.Plugin):
	"""Attempts to add firmware to be tracked by stacki."""

	def provides(self):
		return 'basic'

	def validate_version(self, version, make, model):
		"""Attempts to validate the version number against a version_regex if one is set for the make or model provided."""
		# Attempt to get the version regex entry.
		regex = self.owner.try_get_version_regex(make = make, model = model)
		if regex and not re.search(regex.regex, version, re.IGNORECASE):
			raise ArgError(
				cmd = self.owner,
				arg = 'version',
				msg = (
					f'The format of the version number {version} does not validate based on the regex {regex.regex}'
					f' named {regex.name}{f" with description {regex.description}" if regex.description else ""}.'
				)
			)
		# else there's nothing to check

	def validate_arguments(self, version, params):
		"""Validates that the expected arguments are present and that the optional arguments are specified correctly (if at all).

		Returns the validated arguments if all checks are successful
		"""
		source, make, model, imp, hosts, hash_value, hash_alg = params
		# Require a version name
		if not version:
			raise ArgRequired(cmd = self.owner, arg = 'version')
		# should only be one version name
		if len(version) != 1:
			raise ArgUnique(cmd = self.owner, arg = 'version')

		version_number = version[0]
		# require a source
		if not source:
			raise ParamRequired(cmd = self.owner, param = 'source')
		# require both make and model
		if not make:
			raise ParamRequired(cmd = self.owner, param = 'make')
		if not model:
			raise ParamRequired(cmd = self.owner, param = 'model')
		# require an implementation
		if not imp:
			raise ParamRequired(cmd = self.owner, param = 'imp')
		# require hash_alg to be one of the always present ones
		if hash_alg not in stack.firmware.SUPPORTED_HASH_ALGS:
			raise ParamError(
				cmd = self.owner,
				param = 'hash_alg',
				msg = f'hash_alg must be one of the following: {stack.firmware.SUPPORTED_HASH_ALGS}'
			)
		# validate the version matches the version_regex if one is set.
		self.validate_version(version = version_number, make = make, model = model)
		# Convert hosts to a list if set
		if hosts:
			hosts = [host.strip() for host in hosts.split(",") if host.strip()]
			# Validate the hosts exist.
			self.owner.getHosts(args = hosts)

		return (version_number, source, make, model, imp, hosts, hash_value, hash_alg)

	def add_related_entries(self, make, model, imp, cleanup):
		"""Adds the related database entries if they do not exist."""
		# create the implementation if it doesn't already exist
		if not self.owner.imp_exists(imp = imp):
			self.owner.call(command = 'add.firmware.imp', args = [imp])
			cleanup.callback(self.owner.call, command = 'remove.firmware.imp', args = [imp])

		# create the make if it doesn't already exist
		if not self.owner.make_exists(make = make):
			self.owner.call(command = 'add.firmware.make', args = [make])
			cleanup.callback(self.owner.call, command = 'remove.firmware.make', args = [make])

		# create the model if it doesn't already exist
		if not self.owner.model_exists(make = make, model = model):
			self.owner.call(command = 'add.firmware.model', args = [model, f'make={make}', f'imp={imp}'])
			cleanup.callback(self.owner.call, command = 'remove.firmware.model', args = [model, f'make={make}'])

	def run(self, args):
		params, version = args
		params = self.owner.fillParams(
			names = [
				('source', ''),
				('make', ''),
				('model', ''),
				('imp', ''),
				('hosts', ''),
				('hash', None),
				('hash_alg', 'md5')
			],
			params = params
		)

		# validate the args before use
		version, source, make, model, imp, hosts, hash_value, hash_alg = self.validate_arguments(
			version = version,
			params = params
		)

		# ensure the firmware version doesn't already exist for the given model
		if self.owner.firmware_exists(make, model, version):
			raise ArgError(
				cmd = self.owner,
				arg = 'version',
				msg = f'The firmware version {version} for make {make} and model {model} already exists.'
			)

		# we use ExitStack to hold our cleanup operations and roll back should something fail.
		with ExitStack() as cleanup:
			# fetch the firmware from the source and copy the firmware into a stacki managed file
			try:
				file_path = stack.firmware.fetch_firmware(
					source = source,
					make = make,
					model = model
				)

				def file_cleanup():
					"""Remove the file if it exists.

					Needed because "stack remove firmware" also removes the file
					and that might have been run as part of the exit stack unwinding.
					"""
					if file_path.exists():
						file_path.unlink()

				cleanup.callback(file_cleanup)
			except stack.firmware.FirmwareError as exception:
				raise ParamError(
					cmd = self.owner,
					param = 'source',
					msg = f'{exception}'
				)
			# calculate the file hash and compare it with the user provided value if present.
			try:
				file_hash = stack.firmware.calculate_hash(file_path = file_path, hash_alg = hash_alg, hash_value = hash_value)
			except stack.firmware.FirmwareError as exception:
				raise ParamError(
					cmd = self.owner,
					param = 'hash',
					msg = f'{exception}'
				)

			# add make and model database entries if needed.
			self.add_related_entries(make = make, model = model, imp = imp, cleanup = cleanup)

			# get the ID of the model to associate with
			model_id = self.owner.get_model_id(make, model)
			# insert into DB associated with make + model
			self.owner.db.execute(
				'''
				INSERT INTO firmware (
					model_id,
					source,
					version,
					hash_alg,
					hash,
					file
				)
				VALUES (%s, %s, %s, %s, %s, %s)
				''',
				(model_id, source, version, hash_alg, file_hash, str(file_path))
			)
			cleanup.callback(self.owner.call, command = "remove.firmware", args = [version, f"make={make}", f"model={model}"])

			# if hosts are provided, set the firmware relation
			if hosts:
				self.owner.call(command = "add.firmware.mapping", args = [*hosts, f"version={version}", f"make={make}", f"model={model}"])

			# everything went down without a problem, dismiss the cleanup
			cleanup.pop_all()

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

class Plugin(stack.commands.Plugin):
	"""Attempts to remove firmware mappings based on the provided arguments."""

	def provides(self):
		return "basic"

	def get_firmware_mappings_to_remove(self, hosts, versions, make, model):
		"""Gets the mappings to remove using the provided arguments as a filter."""
		# If versions and hosts are specified, get the specific mappings to remove for the hosts
		if versions and hosts:
			mappings_to_remove = [
				row[0] for row in self.owner.db.select(
					"""
					firmware_mapping.id
					FROM firmware_mapping
						INNER JOIN nodes
							ON firmware_mapping.node_id = nodes.ID
						INNER JOIN firmware
							ON firmware_mapping.firmware_id = firmware.id
						INNER JOIN firmware_model
							ON firmware.model_id = firmware_model.id
						INNER JOIN firmware_make
							ON firmware_model.make_id = firmware_make.id
					WHERE nodes.Name IN %s AND firmware.version IN %s AND firmware_make.name=%s AND firmware_model.name=%s
					""",
					(hosts, versions, make, model)
				)
			]
		# Else if make, model, and hosts are specified, remove all mappings for that make and model for the specified hosts
		elif make and model and hosts:
			mappings_to_remove = [
				row[0] for row in self.owner.db.select(
					"""
					firmware_mapping.id
					FROM firmware_mapping
						INNER JOIN nodes
							ON firmware_mapping.node_id = nodes.ID
						INNER JOIN firmware
							ON firmware_mapping.firmware_id = firmware.id
						INNER JOIN firmware_model
							ON firmware.model_id = firmware_model.id
						INNER JOIN firmware_make
							ON firmware_model.make_id = firmware_make.id
					WHERE nodes.Name IN %s AND firmware_make.name=%s AND firmware_model.name=%s
					""",
					(hosts, make, model)
				)
			]
		# Else if make and hosts are specified, remove all mappings for that make for the specified hosts.
		elif make and hosts:
			mappings_to_remove = [
				row[0] for row in self.owner.db.select(
					"""
					firmware_mapping.id
					FROM firmware_mapping
						INNER JOIN nodes
							ON firmware_mapping.node_id = nodes.ID
						INNER JOIN firmware
							ON firmware_mapping.firmware_id = firmware.id
						INNER JOIN firmware_model
							ON firmware.model_id = firmware_model.id
						INNER JOIN firmware_make
							ON firmware_model.make_id = firmware_make.id
					WHERE nodes.Name IN %s AND firmware_make.name=%s
					""",
					(hosts, make)
				)
			]
		# Else only hosts are specified, so remove all firmware mappings from the specified hosts
		elif hosts:
			mappings_to_remove = [
				row[0] for row in self.owner.db.select(
					"""
					firmware_mapping.id
					FROM firmware_mapping
						INNER JOIN nodes
							ON firmware_mapping.node_id = nodes.ID
						INNER JOIN firmware
							ON firmware_mapping.firmware_id = firmware.id
						INNER JOIN firmware_model
							ON firmware.model_id = firmware_model.id
						INNER JOIN firmware_make
							ON firmware_model.make_id = firmware_make.id
					WHERE nodes.Name IN %s
					""",
					(hosts,)
				)
			]
		# Else if versions are specified, get all mappings for the specified firmware versions.
		elif versions:
			mappings_to_remove = [
				row[0] for row in self.owner.db.select(
					"""
					firmware_mapping.id
					FROM firmware_mapping
						INNER JOIN firmware
							ON firmware_mapping.firmware_id = firmware.id
						INNER JOIN firmware_model
							ON firmware.model_id = firmware_model.id
						INNER JOIN firmware_make
							ON firmware_model.make_id = firmware_make.id
					WHERE firmware.version IN %s AND firmware_make.name=%s AND firmware_model.name=%s
					""",
					(versions, make, model)
				)
			]
		# Else if make and model are specified, remove all mappings for that make and model for all hosts
		elif make and model:
			mappings_to_remove = [
				row[0] for row in self.owner.db.select(
					"""
					firmware_mapping.id
					FROM firmware_mapping
						INNER JOIN firmware
							ON firmware_mapping.firmware_id = firmware.id
						INNER JOIN firmware_model
							ON firmware.model_id = firmware_model.id
						INNER JOIN firmware_make
							ON firmware_model.make_id = firmware_make.id
					WHERE firmware_make.name=%s AND firmware_model.name=%s
					""",
					(make, model)
				)
			]
		# Else if make is specified, remove all mappings for that make for all hosts.
		elif make:
			mappings_to_remove = [
				row[0] for row in self.owner.db.select(
					"""
					firmware_mapping.id
					FROM firmware_mapping
						INNER JOIN firmware
							ON firmware_mapping.firmware_id = firmware.id
						INNER JOIN firmware_model
							ON firmware.model_id = firmware_model.id
						INNER JOIN firmware_make
							ON firmware_model.make_id = firmware_make.id
					WHERE firmware_make.name=%s
					""",
					(make,)
				)
			]
		# otherwise remove all mappings
		else:
			mappings_to_remove = [
				row[0] for row in self.owner.db.select("firmware_mapping.id FROM firmware_mapping")
			]

		return mappings_to_remove

	def run(self, args):
		params, hosts = args
		make, model, versions = self.owner.fillParams(
			names = [
				("make", ""),
				("model", ""),
				("versions", ""),
			],
			params = params
		)

		# process hosts if present
		if hosts:
			# hosts must exist
			hosts = self.owner.getHosts(args = hosts)
		# process make if present
		if make:
			# ensure the make exists
			if not self.owner.make_exists(make = make):
				raise ParamError(
					cmd = self.owner,
					param = "make",
					msg = f"The make {make} doesn't exist."
				)
		# process model if present
		if model:
			# make is now required
			if not make:
				raise ParamRequired(cmd = self.owner, param = "make")
			# ensure the model exists
			if not self.owner.model_exists(make = make, model = model):
				raise ParamError(
					cmd = self.owner,
					param = "model",
					msg = f"The model {model} doesn't exist for make {make}."
				)
		# Process versions if present
		if versions:
			# make and model are now required
			if not make:
				raise ParamRequired(cmd = self.owner, param = "make")
			if not model:
				raise ParamRequired(cmd = self.owner, param = "model")
			# turn a comma separated string into a list of versions and
			# get rid of any duplicate names
			versions = self.owner.remove_duplicates(
				args = (version.strip() for version in versions.split(",") if version.strip())
			)
			# ensure the versions exist
			try:
				self.owner.validate_firmwares_exist(make = make, model = model, versions = versions)
			except CommandError as exception:
				raise ArgError(
					cmd = self.owner,
					arg = "version",
					msg = exception.message()
				)

		mappings_to_remove = self.get_firmware_mappings_to_remove(
			hosts = hosts,
			versions = versions,
			make = make,
			model = model,
		)

		# remove the mappings
		if mappings_to_remove:
			self.owner.db.execute("DELETE FROM firmware_mapping WHERE id IN %s", (mappings_to_remove,))

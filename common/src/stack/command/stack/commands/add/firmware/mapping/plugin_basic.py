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
import stack.commands.list.host.firmware
import stack.commands.sync.host.firmware
from stack.exception import ParamRequired, ParamError, CommandError

class Plugin(stack.commands.Plugin):
	"""Attempts to map firmware versions to hosts."""

	def provides(self):
		return "basic"

	def run(self, args):
		params, args = args
		hosts = self.owner.getHosts(args = args)
		version, make, model, = self.owner.fillParams(
			names = [
				("version", ""),
				("make", ""),
				("model", ""),
			],
			params = params
		)

		# Make is required
		if not make:
			raise ParamRequired(cmd = self.owner, param = "make")
		# The make must exist
		if not self.owner.make_exists(make = make):
			raise ParamError(
				cmd = self.owner,
				param = "make",
				msg = f"Make {make} does not exist."
			)
		# Model is required
		if not model:
			raise ParamRequired(cmd = self.owner, param = "make")
		# The model must exist
		if not self.owner.model_exists(make = make, model = model):
			raise ParamError(
				cmd = self.owner,
				param = "model",
				msg = f"Model {model} does not exist for make {make}."
			)
		# Version is required
		if not version:
			raise ParamRequired(cmd = self.owner, param = "version")
		# The version must exist
		if not self.owner.firmware_exists(make = make, model = model, version = version):
			raise ParamError(
				cmd = self.owner,
				param = "version",
				msg = f"Firmware version {version} does not exist for make {make} and model {model}."
			)
		# The mappings must not already exist
		existing_mappings = [
			f"{host} mapped to firmware {version} for make {make} and model {model}" for host, make, model, version in (
				row for row in self.owner.db.select(
					"""
					nodes.Name, firmware_make.name, firmware_model.name, firmware.version
					FROM firmware_mapping
						INNER JOIN nodes
							ON firmware_mapping.node_id = nodes.ID
						INNER JOIN firmware
							ON firmware_mapping.firmware_id = firmware.id
						INNER JOIN firmware_model
							ON firmware.model_id = firmware_model.id
						INNER JOIN firmware_make
							ON firmware_model.make_id = firmware_model.id
					WHERE nodes.Name IN %s AND firmware_make.name = %s AND firmware_model.name = %s AND firmware.version = %s
					""",
					(hosts, make, model, version)
				)
			)
		]
		if existing_mappings:
			existing_mappings = "\n".join(existing_mappings)
			raise CommandError(cmd = self.owner, msg = f"The following firmware mappings already exist:\n{existing_mappings}")

		# Get the ID's of all the hosts
		node_ids = (
			row[0] for row in self.owner.db.select("ID FROM nodes WHERE Name in %s", (hosts,))
		)
		# Get the firmware version ID
		firmware_id = self.owner.get_firmware_id(make = make, model = model, version = version)

		# Add the mapping entries.
		self.owner.db.execute(
			"""
			INSERT INTO firmware_mapping (
				node_id,
				firmware_id
			)
			VALUES (%s, %s)
			""",
			[(node_id, firmware_id) for node_id in node_ids],
			many = True,
		)

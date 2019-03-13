'''
Add a foreign key constraint to the ib_memberships table which removes memberships if the switch, partition, or associated interface are removed.

step 1 corrects any invalid references to removed switches.
step 2 corrects any invalid references to removed interfaces.
step 3 corrects any invalid references to removed partitions
step 4 adds a constraint for switches, and has a rollback to remove it.
step 5 adds a constraint for interfaces, and has a rollback to remove it.
step 6 adds a constraint for ib partitions, and has a rollback to remove it.
'''

from yoyo import step

__depends__ = {}

steps = [
	step(
		'''DELETE FROM ib_memberships
		WHERE switch NOT IN (SELECT id FROM nodes);'''
	),
	step(
		'''DELETE FROM ib_memberships
		WHERE interface NOT IN (SELECT id FROM networks);'''
	),
	step(
		'''DELETE FROM ib_memberships
		WHERE part_name NOT IN (SELECT id FROM ib_partitions);'''
	),
	step(
		'''ALTER TABLE ib_memberships
		ADD CONSTRAINT ib_memberships_switch_id_fk FOREIGN KEY (switch)
			REFERENCES nodes(id) ON DELETE CASCADE;''',
		'''ALTER TABLE ib_memberships
		DROP FOREIGN KEY ib_memberships_switch_id_fk;'''
	),
	step(
		'''ALTER TABLE ib_memberships
		ADD CONSTRAINT ib_memberships_interface_id_fk FOREIGN KEY (interface)
			REFERENCES networks(id) ON DELETE CASCADE;''',
		'''ALTER TABLE ib_memberships
		DROP FOREIGN KEY ib_memberships_interface_id_fk;'''
	),
	step(
		'''ALTER TABLE ib_memberships
		ADD CONSTRAINT ib_memberships_partition_id_fk FOREIGN KEY (part_name)
			REFERENCES ib_partitions(id) ON DELETE CASCADE;''',
		'''ALTER TABLE ib_memberships
		DROP FOREIGN KEY ib_memberships_partition_id_fk;'''
	),
]

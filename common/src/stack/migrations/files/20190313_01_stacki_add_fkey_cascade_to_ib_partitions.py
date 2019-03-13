'''
Add a foreign key constraint to the ib_partitions table which removes partitions if the owning switch is removed.

step 1 corrects any invalid references to removed switches.
step 2 adds the constraint, and has a rollback to remove it.
'''

from yoyo import step

__depends__ = {}

steps = [
	step(
		'''DELETE FROM ib_partitions
		WHERE switch NOT IN (SELECT id FROM nodes);'''
	),
	step(
		'''ALTER TABLE ib_partitions
		ADD CONSTRAINT ib_switch_id_fk FOREIGN KEY (switch)
			REFERENCES nodes(id) ON DELETE CASCADE;''',
		'''ALTER TABLE ib_partitions
		DROP FOREIGN KEY ib_switch_id_fk;'''
	),
]

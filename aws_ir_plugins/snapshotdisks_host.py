import logging


logger = logging.getLogger(__name__)


class Plugin(object):
    def __init__(
        self,
        boto_session,
        compromised_resource,
        dry_run
    ):

        self.session = boto_session
        self.compromised_resource = compromised_resource
        self.compromise_type = compromised_resource['compromise_type']
        self.dry_run = dry_run
        self.setup()

    def setup(self):
        self.client = self._get_client()
        self.snapshot_volumes()

    def _get_client(self):
        client = self.session.client(
            service_name='ec2'
        )
        return client

    def _get_resource(self):
        return self.session.resource('ec2')

    def _create_snapshot(self, volume_id, description):
        try:
            response = self.client.create_snapshot(
                DryRun=self.dry_run,
                VolumeId=volume_id,
                Description=description
            )
            return response
            logger.info('A snapshot was taken'
                        ' for volume {v}.'.format(v=volume_id))
        except Exception as e:
            print(e)
            logger.info(
                'There was an error taking the '
                'snapshot for volume {v}.'.format(v=volume_id))
            return None

    def _tag_snapshot(self, snapshot_id):
        if snapshot_id is not None:
            ec2 = self._get_resource()
            snapshot = ec2.Snapshot(snapshot_id)
            snapshot.create_tags(
                Tags=[
                    dict(
                        Key='cr-case-number',
                        Value=self.compromised_resource['case_number']
                    )
                ]
            )
            return True
        else:
            return False

    def snapshot_volumes(self):
        logger.info('Attempting snapshots on compromised resource.')

        for volume_id in self.compromised_resource['volume_ids']:
            description = 'Snapshot of {vid} for case {cn}'.format(
                vid=volume_id,
                cn=self.compromised_resource['case_number']
            )

            snapshot = self._create_snapshot(volume_id, description)
            if snapshot is not None:
                snapshot_id = snapshot.get('SnapshotId')
                print(self._tag_snapshot(snapshot_id))

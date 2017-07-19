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
        if self.dry_run is not True:
            self.stop_instance()
        else:
            pass

    def validate(self):
        return True

    def _get_client(self):
        client = self.session.client(
            service_name='ec2'
        )
        return client

    def stop_instance(self):
        try:
            response = self.client.stop_instances(
                InstanceIds=[
                    self.compromised_resource['instance_id']
                ],
                Force=True
            )
            logger.info(
                'Stop instance success for instance: {i}'.format(
                    i=self.compromised_resource['instance_id']
                )
            )
        except Exception as e:
            logger.info(
                'Failed to stop instance: {i}, error {e}'.format(
                    i=self.compromised_resource['instance_id'],
                    e=e
                )
            )
        return response

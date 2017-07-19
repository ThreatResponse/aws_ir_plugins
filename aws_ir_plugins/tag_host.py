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
        self.tagged = self.add_incident_tag_to_instance()

    def validate(self):
        instance_id = self.compromised_resource['instance_id']
        response = self.client.describe_instances(
            InstanceIds=[instance_id],
            Filters=[
                {
                    'Name': 'tag-key',
                    'Values': [
                        'cr-case-number'
                    ]
                },
            ],
        )
        if len(response['Reservations']) > 0:
            return True
        else:
            return False

    def _get_client(self):
        client = self.session.client(
            service_name='ec2'
        )
        return client

    def _create_tags(self):
        tag = [
            {
                'Key': 'cr-case-number',
                'Value': self.compromised_resource['case_number']
            }
        ]

        return tag

    def add_incident_tag_to_instance(self):
        instance_id = self.compromised_resource['instance_id']
        try:
            self.client.create_tags(
                DryRun=self.dry_run,
                Resources=[instance_id],
                Tags=self._create_tags()
            )
            return True

        except Exception as e:
            print(e)
            if e.response['Error']['Message'] == """
                Request would have succeeded, but DryRun flag is set.
            """:
                return None
            else:
                raise e

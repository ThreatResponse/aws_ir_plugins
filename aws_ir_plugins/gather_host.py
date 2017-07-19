import base64
import json
import logging
"""Gathers ephemeral data that could be lost on instance termination"""


logger = logging.getLogger(__name__)


class Plugin(object):
    """Initializer takes standard plugin constructor

     added api flag for data persistence in AWS_IR api
    """
    def __init__(
        self,
        boto_session,
        compromised_resource,
        dry_run,
        api=False
    ):

        self.session = boto_session
        self.compromised_resource = compromised_resource
        self.compromise_type = compromised_resource['compromise_type']
        self.dry_run = dry_run
        self.api = api

        """
            These attrs will only be set during API=True
            Added for Readability and AWS_IR data persistence
        """
        self.evidence = {}

        self.setup()

    def setup(self):
        if self.dry_run is not True:
            self.client = self._get_client()
            metadata = self._get_aws_instance_metadata()
            self._log_aws_instance_metadata(metadata)
            console = self._get_aws_instance_console_output()
            self._log_aws_instance_console_output(console)
            self._log_aws_instance_screenshot()
            return True
        else:
            return False

    def validate(self):
        """Can't really validate data gather."""
        return True

    def _get_client(self):
        client = self.session.client(
            service_name='ec2'
        )
        return client

    def _get_aws_instance_metadata(self):
        metadata = self.client.describe_instances(
            Filters=[
                {
                    'Name': 'instance-id',
                    'Values': [
                        self.compromised_resource['instance_id']
                    ]
                }
            ]
        )['Reservations']

        return metadata

    def _log_aws_instance_metadata(self, data):
        if self.api is True:
            self.evidence['metadata.json'] = json.dumps(data)
        else:
            logfile = ("/tmp/{case_number}-{instance_id}-metadata.log").format(
                case_number=self.compromised_resource['case_number'],
                instance_id=self.compromised_resource['instance_id']
            )
            with open(logfile, 'w') as w:
                w.write(str(data))

    def _get_aws_instance_console_output(self):
        output = self.client.get_console_output(
            InstanceId=self.compromised_resource['instance_id']
        )
        return output

    def _log_aws_instance_console_output(self, data):
        if self.api is True:
            self.evidence['console.json'] = json.dumps(data)
        else:
            logfile = ("/tmp/{case_number}-{instance_id}-console.log").format(
                case_number=self.compromised_resource['case_number'],
                instance_id=self.compromised_resource['instance_id']
            )
            with open(logfile, 'w') as w:
                w.write(str(data))
        logger.info(
            'Console logs have been acquired for'
            '{i}'.format(
                i=self.compromised_resource['instance_id']
            )
        )

    def _log_aws_instance_screenshot(self):
        try:
            response = self.client.get_console_screenshot(
                InstanceId=self.compromised_resource['instance_id'],
                WakeUp=True
            )
            if self.api is True:
                self.evidence['screenshot.jpg'] = response['ImageData']
            else:
                logfile = ("/tmp/{case_number}-{instance_id}-screenshot.jpg")\
                    .format(
                        case_number=self.compromised_resource['case_number'],
                        instance_id=self.compromised_resource['instance_id']
                )

                fh = open(logfile, "wb")
                fh.write(base64.b64decode(response['ImageData']))
                fh.close()
            logger.info(
                'Screenshot has been acquired for '
                '{i}'.format(
                    i=self.compromised_resource['instance_id']
                )
            )
        except Exception as e:
            logger.info(
                'There was an error {e} while '
                'fetching the screenshot for {i}'.format(
                    e=e,
                    i=self.compromised_resource['instance_id']
                )
            )

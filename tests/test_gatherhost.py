import boto3
import unittest

from aws_ir_plugins import gather_host
from moto import mock_ec2


class StopHostTest(unittest.TestCase):
    @mock_ec2
    def test_tag_host(self):
        self.ec2 = boto3.client('ec2', region_name='us-west-2')
        session = boto3.Session(region_name='us-west-2')

        ec2_resource = session.resource('ec2')

        instance = ec2_resource.create_instances(
            ImageId='foo',
            MinCount=1,
            MaxCount=1,
            InstanceType='t2.medium',
            KeyName='akrug-key',
        )

        self.compromised_resource = {
            'case_number': '123456',
            'instance_id': instance[0].id,
            'compromise_type': 'host'
        }

        plugin = gather_host.Plugin(
            boto_session=session,
            compromised_resource=self.compromised_resource,
            dry_run=False
        )

        result = plugin.validate()

        assert result is True

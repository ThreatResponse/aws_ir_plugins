import boto3
import unittest

from aws_ir_plugins import disableaccess_key
from moto import mock_iam
from unittest.mock import patch


class DisableKeyTest(unittest.TestCase):
    @mock_iam
    def test_disable_plugin(self):
        self.iam = boto3.client('iam', region_name='us-west-2')
        self.user = self.iam.create_user(
            UserName='bobert'
        )

        self.access_key = self.iam.create_access_key(
            UserName='bobert'
        )

        self.access_key_id = self.access_key['AccessKey']['AccessKeyId']

        self.compromised_resource = {
            'case_number': '123456',
            'access_key_id': self.access_key_id,
            'compromise_type': 'key'
        }
        session = boto3.Session()
        with patch.object(
                disableaccess_key.Plugin,
                '_search_user_for_key',
                return_value='bobert'
        ) as mock_client:

            mock_client.return_value = 'bobert'

            plugin = disableaccess_key.Plugin(
                boto_session=session,
                compromised_resource=self.compromised_resource,
                dry_run=False
            )

            assert plugin.validate() is not None

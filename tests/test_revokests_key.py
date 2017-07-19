import boto3
import json
import unittest

from aws_ir_plugins import revokests_key
from moto import mock_iam
from unittest.mock import patch


class RevokeSTSTest(unittest.TestCase):
    @mock_iam
    def test_jinja_rendering(self):
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
        session = None
        with patch.object(
                revokests_key.Plugin, '_get_client', return_value=self.iam
        ) as mock_client:

            mock_client.return_value = self.iam
            plugin = revokests_key.Plugin(
                boto_session=session,
                compromised_resource=self.compromised_resource,
                dry_run=True
            )

        assert json.loads(plugin.template)

    @mock_iam
    @patch('aws_ir_plugins.revokests_key.Plugin')
    def test_plugin(self, mock_revokests):
        self.iam = boto3.client('iam', region_name='us-west-2')
        mock_revokests._get_username_for_key.return_value = 'bobert'
        mock_revokests.validate.return_value = 'True'

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

        with patch.object(
                revokests_key.Plugin, '_get_client', return_value=self.iam
        ) as mock_client:

            mock_client.return_value = self.iam
            plugin = revokests_key.Plugin(
                client=self.iam,
                compromised_resource=self.compromised_resource,
                dry_run=False
            )

        res1 = plugin.setup()

        res2 = plugin.validate()

        self.policies = self.iam.list_user_policies(
            UserName='bobert'
        )

        assert res1 is not None
        assert res2 is not None

import boto3
import unittest

from aws_ir_plugins import snapshotdisks_host
from moto import mock_ec2
from unittest.mock import patch


class SnapshotDisksTest(unittest.TestCase):
    @mock_ec2
    def test_disk_snapshot(self):
        self.ec2 = boto3.client('ec2', region_name='us-west-2')

        volume = self.ec2.create_volume(
            AvailabilityZone='us-west-2',
            Encrypted=False,
            Size=1024,
            VolumeType='standard',
        )

        self.compromised_resource = {
            'case_number': '123456',
            'volume_ids': [volume.get('VolumeId')],
            'compromise_type': 'host'
        }

        session = boto3.Session(region_name='us-west-2')
        with patch.object(
                snapshotdisks_host.Plugin, '_get_client', return_value=self.ec2
        ) as mock_client:

            mock_client.return_value = self.ec2
            plugin = snapshotdisks_host.Plugin(
                boto_session=session,
                compromised_resource=self.compromised_resource,
                dry_run=False
            )

            assert plugin is not None

import boto3
import unittest

from aws_ir_plugins import examineracl_host
from moto import mock_ec2


class ExaminerACLHostTest(unittest.TestCase):
    @mock_ec2
    def test_tag_host(self):
        self.ec2 = boto3.client('ec2', region_name='us-west-2')
        session = boto3.Session(region_name='us-west-2')

        ec2_resource = session.resource('ec2')

        vpc = self.ec2.create_vpc(
            CidrBlock='10.0.0.0/8',
            InstanceTenancy='default'
        )

        subnet = self.ec2.create_subnet(
            CidrBlock='10.0.1.0/24',
            VpcId=vpc['Vpc']['VpcId']
        )

        vpc_id = vpc['Vpc']['VpcId']

        sec_group = self.ec2.create_security_group(
            Description='Test test',
            GroupName='test',
            VpcId=vpc_id,
        )

        instance = ec2_resource.create_instances(
            ImageId='foo',
            MinCount=1,
            MaxCount=1,
            InstanceType='t2.medium',
            KeyName='akrug-key',
            Placement={
                'AvailabilityZone': subnet['Subnet']['AvailabilityZone']
            },
            SubnetId=subnet['Subnet']['SubnetId'],
            SecurityGroupIds=[
                sec_group['GroupId']
            ]
        )

        self.compromised_resource = {
            'case_number': '123456',
            'instance_id': instance[0].id,
            'vpc_id': vpc_id,
            'compromise_type': 'host',
            'examiner_cidr_range': '8.8.8.8/32'
        }

        plugin = examineracl_host.Plugin(
            boto_session=session,
            compromised_resource=self.compromised_resource,
            dry_run=False
        )

        result = plugin.validate()

        assert result is True

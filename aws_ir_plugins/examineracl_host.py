import logging
""" Allows the examiner cidr range access to the instance. """

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
        self.examiner_cidr_range = compromised_resource['examiner_cidr_range']
        self.dry_run = dry_run

        self.setup()

    def setup(self):
        self.client = self._get_client()
        sg = self._create_isolation_security_group()
        if self.exists is not True:
            acl = self._create_network_acl()
            self._add_network_acl_entries(acl)
            self._add_security_group_rule(sg)
        self._add_security_group_to_instance(sg)

        """Conditions that can not be dry_run"""
        if self.dry_run is not False:
            self._add_security_group_rule(sg)
            self._add_security_group_to_instance(sg)

    def validate(self):
        """Validate that the instance is in fact isolated"""
        if self.sg_name is not None:
            return True
        else:
            return False

    def _get_client(self):
        client = self.session.client(
            service_name='ec2'
        )
        return client

    def _create_isolation_security_group(self):
        try:
            security_group_result = self.client.create_security_group(
                DryRun=self.dry_run,
                GroupName=self._generate_security_group_name(),
                Description="ThreatResponse Examiner Access Security Group",
                VpcId=self.compromised_resource['vpc_id'],

            )
            self.exists = False

        except Exception:
            logger.info(
                "Security group already exists. Attaching existing SG."
            )
            self.exists = True
            security_group_result = self.client.describe_security_groups(
                DryRun=self.dry_run,
                GroupNames=[
                    self._generate_security_group_name()
                ]
            )['SecurityGroups'][0]
        return security_group_result['GroupId']

    def _add_security_group_rule(self, security_group_id):
        try:
            self.client.authorize_security_group_ingress(
                DryRun=self.dry_run,
                GroupId=security_group_id,
                IpProtocol='tcp',
                FromPort=22,
                ToPort=22,
                CidrIp=self.examiner_cidr_range
            )

            self.client.revoke_security_group_egress(
                DryRun=self.dry_run,
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        'IpProtocol': '-1',
                        'IpRanges': [
                            {
                                'CidrIp': '0.0.0.0/0'
                            }
                        ]
                    }
                ]
            )

            self.client.authorize_security_group_egress(
                DryRun=self.dry_run,
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 32000,
                        'ToPort': 65535,
                        'IpRanges': [
                            {
                                'CidrIp': self.examiner_cidr_range
                            }
                        ]
                    }
                ]
            )
        except Exception as e:
            logger.info(
                'There isolation SG could not be added '
                'to instance {i} due to {e}'.format(
                    e=e,
                    i=self.compromised_resource['instance_id']
                )
            )

    def _generate_security_group_name(self):
        sg_name = "examiner-sg-{case_number}-{instance}".format(
            case_number=self.compromised_resource['case_number'],
            instance=self.compromised_resource['instance_id']
        )
        self.sg_name = sg_name
        return sg_name

    def _add_security_group_to_instance(self, group_id):
        try:
            self.client.modify_instance_attribute(
                DryRun=self.dry_run,
                InstanceId=self.compromised_resource['instance_id'],
                Groups=[
                    group_id,
                ],
            )
            return True
        except Exception:
            return False

    def _create_network_acl(self):
        try:
            response = self.client.create_network_acl(
                DryRun=self.dry_run,
                VpcId=self.compromised_resource['vpc_id'],
            )
            return response['NetworkAcl']['NetworkAclId']
        except Exception as e:
            logger.info(
                'There was an error {e} '
                'while creating the nacl'.format(e=e)
            )

    def _add_network_acl_entries(self, acl_id):
        try:
            self.client.create_network_acl_entry(
                DryRun=self.dry_run,
                NetworkAclId=acl_id,
                RuleNumber=1336,
                Protocol='-1',
                RuleAction='allow',
                Egress=True,
                CidrBlock=self.examiner_cidr_range
            )
            return True
        except Exception as e:
            logger.info(
                'There was an error {e} while adding the nacl'.format(e=e)
            )

import datetime
import fnmatch
import logging
import os

from jinja2 import Template


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
        """Method runs the plugin attaching policies to the user in question"""
        self.template = self._generate_inline_policy()
        if self.dry_run is not True:
            self.client = self._get_client()
            username = self._get_username_for_key()
            policy_document = self.__generate_inline_policy()
            self._attach_inline_policy(username, policy_document)
            pass

    def validate(self):
        """Checks the a policy is actually attached"""
        for policy in self._get_policies()['PolicyNames']:
            if policy == "threatresponse-temporal-key-revocation":
                return True
            else:
                pass
        return False

    def _get_client(self):
        client = self.session.client(
            service_name='iam',
            region_name='us-west-2'
        )
        return client

    def _get_policies(self):
        """Returns all the policy names for a given user"""
        username = self._get_username_for_key()
        policies = self.client.list_user_policies(
            UserName=username
        )
        return policies

    def _get_date(self):
        """Returns a date in zulu time"""
        now = datetime.datetime.utcnow().isoformat() + 'Z'
        return now

    def _get_username_for_key(self):
        """Find the user for a given access key"""
        response = self.client.get_access_key_last_used(
            AccessKeyId=self.compromised_resource['access_key_id']
        )
        username = response['UserName']
        return username

    def _generate_inline_policy(self):
        """Renders a policy from a jinja template"""
        template_name = self._locate_file('deny-sts-before-time.json.j2')
        template_file = open(template_name)
        template_contents = template_file.read()
        template_file.close()
        jinja_template = Template(template_contents)
        policy_document = jinja_template.render(
            before_date=self._get_date()
        )
        return policy_document

    def _attach_inline_policy(self, username, policy_document):
        """Attaches the policy to the user"""
        response = self.client.put_user_policy(
            UserName=username,
            PolicyName="threatresponse-temporal-key-revocation",
            PolicyDocument=policy_document
        )
        logger.info(
            'An inline policy has been attached for'
            ' {u} revoking sts tokens.'.format(u=username)
        )
        return response

    def _locate_file(self, pattern, root=os.path.dirname('revokests_key.py')):
        """Locate all files matching supplied filename pattern in and below

        supplied root directory.
        """

        for path, dirs, files in os.walk(os.path.abspath(root)):
            for filename in fnmatch.filter(files, pattern):
                return os.path.join(path, filename)

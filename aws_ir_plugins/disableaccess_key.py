import logging
""" Allows the examiner cidr range access to the instance. """


logger = logging.getLogger(__name__)


class DisableOwnKeyError(RuntimeError):
    """Thrown when a request is made to disable the current key being used."""
    pass


class Plugin(object):
    def __init__(
        self,
        boto_session,
        compromised_resource,
        dry_run
    ):

        self.session = boto_session  # Requires an IAM Client
        self.compromised_resource = compromised_resource
        self.compromise_type = compromised_resource['compromise_type']
        self.dry_run = dry_run

        self.access_key_id = self.compromised_resource['access_key_id']
        self.setup()

    def setup(self):
        """Method runs the plugin"""
        if self.dry_run is not True:
            self.client = self._get_client()
            self._disable_access_key()

    def validate(self):
        """Returns whether this plugin does what it claims to have done"""
        try:
            response = self.client.get_access_key_last_used(
                AccessKeyId=self.access_key_id
            )

            username = response['UserName']
            access_keys = self.client.list_access_keys(
                UserName=username
            )

            for key in access_keys['AccessKeyMetadata']:
                if \
                        (key['AccessKeyId'] == self.access_key_id)\
                        and (key['Status'] == 'Inactive'):
                    return True

            return False
        except Exception as e:
            logger.info(
                "Failed to validate key disable for "
                "key {id} due to: {e}.".format(
                    e=e, id=self.access_key_id
                )
            )
            return False

    def _get_client(self):
        client = self.session.client(
            service_name='iam',
            region_name='us-west-2'
        )
        return client

    def _search_user_for_key(self):
        try:
            response = self.client.get_access_key_last_used(
                AccessKeyId=self.access_key_id
            )
            logger.info(
                "A user for key {id} has been "
                "found proceeding to disable.".format(
                    id=self.access_key_id
                )
            )
            return response['UserName']
        except Exception as e:
            logger.info(
                "A user for key {id} could "
                "not be located due to: {e}.".format(
                    e=e, id=self.access_key_id
                )
            )

    def _disable_access_key(self, force_disable_self=False):
        """This function first checks to see if the key is already disabled\

        if not then it goes to disabling
        """
        client = self.client
        if self.validate is True:
            return
        else:
            try:
                client.update_access_key(
                    UserName=self._search_user_for_key(),
                    AccessKeyId=self.access_key_id,
                    Status='Inactive'
                )
                logger.info(
                    "Access key {id} has "
                    "been disabled.".format(id=self.access_key_id)
                )
            except Exception as e:
                logger.info(
                    "Access key {id} could not "
                    "be disabled due to: {e}.".format(
                        e=e, id=self.access_key_id
                    )
                )

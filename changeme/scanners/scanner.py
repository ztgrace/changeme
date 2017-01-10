class Scanner(object):
    def __init__(self, data, targets, config):
        """
        :param data:
        :param targets:
        :param config:
        """

        # Retrieve value from dictionary        
        if config.custom_creds:
            self.creds = config.custom_creds
        else:
            self.creds = data['auth']['credentials']

        self.contributor = data.get('contributor', None)
        self.name = data.get('name', None)
        self.type = data['auth'].get('type', None)

        if config.port:
            self.port = config.port
        else:
            self.port = data.get('default_port', None)

        if config.ssl:
            self.ssl = config.ssl
        else:
            self.ssl = data.get('ssl', None)

        self.targets = targets
        self.config = config
        self.logger = config.logger

    def _class_name(self):
        return self.__class__.__name__

class QueueMessage:

    STATUS_OK = 0
    STATUS_NIPAP_ERROR = 1
    STATUS_ERROR = 2

    TYPE_STATUS = 0
    TYPE_PREFIXES = 1
    TYPE_VRFS = 2
    TYPE_POOLS = 3

    def __init__(self, data_type, data, status=STATUS_OK, callback=None):
        self.type = data_type
        self.data = data
        self.status = status
        self.callback = callback

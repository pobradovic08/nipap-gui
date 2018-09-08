class QueueMessage:

    STATUS_OK = 0
    STATUS_NIPAP_ERROR = 1
    STATUS_ERROR = 2

    TYPE_STATUS = 0
    TYPE_PREFIXES = 1
    TYPE_VRFS = 2
    TYPE_POOLS = 3

    def __init__(self, type, data, status):
        self.type = type
        self.data = data
        self.status = status

module Asymy
    module Commands
        SLEEP = 0
        QUIT = 1
        INIT_DB = 2
        QUERY = 3
        FIELD_LIST = 4
        CREATE_DB = 5
        DROP_DB = 6
        REFRESH = 7
        SHUTDOWN = 8
        STATISTICS = 9
        PROCESS_INFO = 0xa
        CONNECT = 0xb
        PROCESS_KILL = 0xc
        DEBUG = 0xd
        PING = 0xe
        TIME = 0xf
        DELAYED_INSERT = 0x10
        CHANGE_USER = 0x11
        BINLOG_DUMP = 0x12
        TABLE_DUMP = 0x13
        CONNECT_OUT = 0x14
        REGISTER_SLAVE = 0x15
        STMT_PREPARE = 0x16
        STMT_EXECUTE = 0x17
        STMT_SEND_LONG_DATA = 0x18
        STMT_CLOSE = 0x19
        SET_OPTION = 0x1b
        STMT_FETCH = 0x1c
    end

    module Capabilities
        LONG_PASSWORD = 1
        FOUND_ROWS = 2
        LONG_FLAG = 4
        CONNECT_WITH_DB = 8
        NO_SCHEMA = 16
        COMPRESS = 32
        ODBC = 64
        LOCAL_FILES = 128
        IGNORE_SPACE    = 256
        PROTOCOL_41 = 512
        INTERACTIVE = 1024
        SSL = 2048
        IGNORE_SIGPIPE = 4096
        TRANSACTIONS = 8192
        RESERVED = 16384
        SECURE_CONNECTION = 32768
        MULTI_STATEMENTS = 65536
        MULTI_RESULTS = 131072
    end

    module FieldTypes
        DECIMAL = 0x00
        TINY = 0x01
        SHORT = 0x02
        LONG = 0x03
        FLOAT = 0x04
        DOUBLE = 0x05
        NULL = 0x06
        TIMESTAMP = 0x07
        LONGLONG = 0x08
        INT24 = 0x09
        DATE = 0x0a
        TIME = 0x0b
        DATETIME = 0x0c
        YEAR = 0x0d
        NEWDATE = 0x0e
        VARCHAR  = 0x0f
        BIT = 0x10
        NEWDECIMAL = 0xf6
        ENUM = 0xf7
        SET = 0xf8
        TINY_BLOB = 0xf9
        MEDIUM_BLOB = 0xfa
        LONG_BLOB = 0xfb
        BLOB = 0xfc
        VAR_STRING = 0xfd
        STRING = 0xfe
        GEOMETRY = 0xff
    end
    FieldTypes.extend(ModuleX)

    module FieldFlags
        NOT_NULL = 0x0001
        PRI_KEY = 0x0002
        UNIQUE_KEY = 0x0004
        MULTIPLE_KEY = 0x0008
        BLOB = 0x0010
        UNSIGNED = 0x0020
        ZEROFILL = 0x0040
        BINARY = 0x0080
        ENUM = 0x0100
        AUTO_INCREMENT = 0x0200
        TIMESTAMP = 0x0400
        SET = 0x0800
    end
end

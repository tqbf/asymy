require File.dirname(__FILE__) + '/asymy'

module Asymy

    # I'm thinking, one per connection
    class Connection
        def initialize(opts={})
            @target = opts[:target]
            @port = opts[:port]
            @password = opts[:password].extend(StringX)
            @database = opts[:database].extend(StringX)
            @username = opts[:username].extend(StringX)

            @queue = []

            @state = :preauth

            reco
        end

        # If I exec'd a statement right now, would it run right now? You probably
        # don't care. Just call Connection#exec and hope.
        def ready?
            self.state == :ready
        end

        # Is there an error on the connection? Since I basically don't handle errors
        # at all right now, and barely even catch them, your best bet is to give up.
        def error?
            self.error || false
        end

        # Queue up an SQL command, and, if the channel is open, send it. Takes a
        # block argument that receives the results, in two arguments, fields (an array of hashes)
        # and rows (an array of strings)
        def exec(cmd, &block)
            @queue << [cmd.extend(StringX), block, Commands::QUERY]
            @fp.inject
        end

        def prepare(cmd, &block)
            @queue << [cmd.extend(StringX), block, Commands::STMT_PREPARE]
            @fp.inject
        end

        def execute_prepared(args, &block)
            @queue << [args, block, Commands::STMT_EXECUTE]
            @fp.inject
        end

        # no user-servicable parts below (attrs used to communicate with module)

        attr_reader :password
        attr_reader :database
        attr_reader :username
        attr_accessor :state
        attr_accessor :error
        attr_accessor :queue

        private

        # EM administrivia: the actual I/O for the connection is handled in a module mixed
        # in to its own connection object. XXX factor this code out into Asymy#Connection, leave
        # only stubs.
        module Session
            attr_accessor :bp

            # EM's idiosyncratic initializer
            def post_init; @framer = Framer.new; end

            # receive 1-48739 bytes of data, which may contain one, two, zero, or 5.7
            # MySQL packets.
            def receive_data(buf)
                @framer << buf
                while @framer.complete?
                    num, packet = @framer.next_buffer
                    receive_packet(num, packet)
                end
            end

            # receive a whole MySQL packet and run the state machine
            def receive_packet(num, packet)
                # special case errors until I waste the time to scan them to see if they're
                # 4.0 or 4.1 packets. XXX
                if packet[0].ord == 0xFF
                    self.error = packet[3..-1]
                    self.state = :error
                end

                def packet.eof?; self[0].ord == 0xfe; end
                def packet.ok?; self[0].ord == 0x00; end

                case self.state
                when :preauth
                    handle_preauth(num, Packets::Greeting.new(packet))
                when :auth_sent
                    handle_postauth(num, Packets::OK.new(packet))

                    # queries on a MySQL connection are synchronous. The response
                    # packets are:
                    # - ResultSet packet (which basically just says "OK")
                    # - Field packets (describing columns)
                    # - EOF (no more fields)
                    # - RowData packets (describing a row)
                    # - EOF (no more rows)

                when :ready
                    inject
                when :awaiting_result_set
                    # XXX just ignore for now
                    self.state = :awaiting_fields
                when :awaiting_fields
                    if packet.eof?
                        self.state = :awaiting_rows
                    else
                        handle_field(num, Packets::Field.new(packet))
                    end
                when :awaiting_rows
                    if packet.eof?
                        @cb.call(@fields, @rows)
                        @fields = nil
                        @rows = nil
                        ready!
                    else
                        # rows have a variable number of variable-length strings, and no other
                        # structure, so just hand the raw data off.
                        handle_row(num, packet)
                    end
                when :awaiting_statement_handle
                    if packet.ok?
                        handle_statement_handle(num, Packets::PrepareOk.new(packet))
                    else
                        # XXX handle this case
                        @state = :error
                    end
                when :awaiting_prepared_params
                    if packet.eof?
                        @state = :waiting_prepared_fields
                    else
                        # I cannot for the life of me figure out what I'm supposed
                        # to do with these --- using mysql-ruby, I can't get them
                        # to change based on their type. Why does MySQL send them?
                        # I figured it'd be to let me enforce types on the params.
                    end
                when :awaiting_prepared_fields
                    if packet.eof?
                        @cb.call(@stmt)
                        @cb, @stmt, @expect_params, @expect_columns = nil, nil, nil, nil
                        ready!
                    else
                        # I guess I could cache these? But why bother? MySQL is just
                        # going to send them again. This protocol confuses and infuriates us!
                    end
                when :error
                    pp self.error
                else
                    raise "don't know how to handle"
                end
            end

            def ready!; self.state = :ready; inject; end

            def inject
                return if not ready?

                # this is going to get untidy real fast XXX

                if(now = self.queue.slice!(0))
                    @cb = now[1]
                    case now[2]
                    when Commands::QUERY
                        self.state = :awaiting_result_set
                        p = Packets::Command.new
                        p.command = Commands::QUERY
                        p.arg = now[0]
                        send_data(p.marshall)
                    when Commands::STMT_PREPARE
                        self.state = :awaiting_statement_handle
                        p = Packets::Prepare.new
                        p.query = now[0]
                        send_data(p.marshall)
                    when Commands::STMT_EXECUTE

                    else
                        raise "wtf?"
                    end
                end
            end

            def handle_preauth(num, greeting)
                response = self.password.crypt(greeting.challenge_head + greeting.challenge_tail) unless self.password.empty?
                response ||= "".extend(StringX)

                a = Packets::Authenticate.new
                a.client_flags = (Capabilities::LONG_PASSWORD |
                                  Capabilities::LONG_FLAG |
                                  Capabilities::CONNECT_WITH_DB |
                                  Capabilities::LOCAL_FILES |
                                  Capabilities::PROTOCOL_41 |
                                  Capabilities::INTERACTIVE |
                                  Capabilities::TRANSACTIONS |
                                  Capabilities::SECURE_CONNECTION | # heh
                                  Capabilities::MULTI_STATEMENTS |
                                  Capabilities::MULTI_RESULTS)
                a.charset_number = greeting.server_language
                a.name = self.username
                a.response = response
                a.database = self.database

                send_data(a.marshall(num+1))

                self.state = :auth_sent
            end

            def handle_postauth(num, ok)
                ready!
            end

            def handle_field(num, field)
                @fields ||= []
                fh = Hash.new
                fh[:table] = field.table
                fh[:name] = field.name
                fh[:length] = field.length
                fh[:type] = field.type
                fh[:flags] = field.flags
                fh[:decimals] = field.decimals
                @fields << fh
            end

            def handle_row(num, row)
                @rows ||= []

                rv = []
                while not row.empty?
                    rv << row.shift_lcstring
                end

                @rows << rv
            end

            def handle_statement_handle(num, ok)
                @stmt = PreparedStatement.new(:backpointer => @bp,
                                              :handle => ok.stmt_id)
                @expect_params = @stmt.parameters
                @expect_columns = @stmt.columns
                if @expect_params > 0
                    @state = :awaiting_prepared_params
                else
                    @state = :awaiting_prepared_columns
                end
            end

            def method_missing(meth, *args); @bp.send(meth, *args); end
        end

        def reco
            EventMachine::connect(@target, @port, Session) {|c| c.bp = self; @fp = c;}
        end

        public
    end
end

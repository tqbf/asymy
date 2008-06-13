require File.dirname(__FILE__) + '/asymy'

require 'stringio'

# XXX for debugging --- ditch both these methods when we're done

class Fixnum; def printable?; self >= 0x20 && self <= 0x7e; end; end

class String
    if RUBY_VERSION[0..2] != '1.9'
        def hexdump(capture=false)
            sio = StringIO.new
            rem = size - 1
            off = 0

            while rem > 0
                pbuf = ""
                pad = (15 - rem) if rem < 16
                pad ||= 0

                sio.write(("0" * (8 - (x = off.to_s(16)).size)) + x + "  ")

                0.upto(15-pad) do |i|
                    c = self[off]
                    x = c.to_s(16)
                    sio.write(("0" * (2 - x.size)) + x + " ")
                    if c.printable?
                        pbuf << c
                    else
                        pbuf << "."
                    end
                    off += 1
                    rem -= 1
                    sio.write(" ") if i == 7
                end

                sio.write("-- " * pad) if pad > 0
                sio.write(" |#{ pbuf }|\n")
            end

            sio.rewind()
            if capture
                sio.read()
            else
                puts sio.read()
            end
        end
    end
end

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
            @queue << [cmd.extend(StringX), block]
            inject if ready?
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
                    if packet[0].ord == 0xfe
                        self.state = :awaiting_rows
                    else
                        handle_field(num, Packets::Field.new(packet))
                    end
                when :awaiting_rows
                    if packet[0].ord == 0xfe
                        @cb.call(@fields, @rows)
                        @fields = nil
                        @rows = nil
                        self.state = :ready
                        inject
                    else
                        # rows have a variable number of variable-length strings, and no other
                        # structure, so just hand the raw data off.
                        handle_row(num, packet)
                    end
                when :error
                    pp self.error
                else
                    raise "don't know how to handle"
                end
            end

            def inject
                if(now = self.queue.slice!(0))
                    @cb = now[1]
                    self.state = :awaiting_result_set
                    p = Packets::Command.new
                    p.command = Commands::QUERY
                    p.arg = now[0]
                    send_data(p.marshall)
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
                self.state = :ready
                inject
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

            def method_missing(meth, *args); @bp.send(meth, *args); end
        end

        def reco
            EventMachine::connect(@target, @port, Session) {|c| c.bp = self}
        end

        public
    end
end

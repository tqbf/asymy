require File.dirname(__FILE__) + '/asymy'

module Asymy
    class Framer < String
        include StringX

        def complete?
            return false if (sz = size()) < 4
            return false if sz < (to_l24() + 4)
            return true
        end

        def next_buffer
            sz = shift_l24()
            num = slice!(0).ord
            return num, slice!(0, sz).extend(StringX)
        end
    end

    module Packets
        class Packet
            def self.field(n, t, default=nil)
                @@fields ||= Hash.new {|h, k| h[k] = []}
                @@fields[self] << [n, t, default]
                attr_accessor n
            end

            def initialize(buf=nil)
                if buf
                    @@fields[self.class].each do |tup|
                        sym = "@#{ tup[0] }".intern
                        if (t = tup[1].to_s)[0].ord.chr == "r"
                            instance_variable_set sym, buf.shift_r(t[1..-1].to_i)
                        else
                            instance_variable_set sym, buf.send("shift_#{ t }")
                        end
                    end
                else
                    @@fields[self.class].each do |tup|
                        if tup[2]
                            sym = "@#{ tup[0] }".intern
                            instance_variable_set sym, tup[2]
                        end
                    end
                end
            end

            def marshall(num=0)
                m = @@fields[self.class].map do |tup|
                    sym = "@#{ tup[0] }".intern
                    t = tup[1].to_s
                    t = "r" if t[0].ord.chr == "r"
                    instance_variable_get(sym).send("to_#{ t }")
                end.join("")

                (m.size.to_l24 + num.chr + m).extend(StringX)
            end
        end

        class Greeting < Packet
            field :protocol_version, :l8
            field :server_version, :asciiz
            field :thread_id, :l32
            field :challenge_head, :r8
            field :zero, :l8
            field :server_capabilities, :l16
            field :server_language, :l8
            field :server_status, :l16
            field :padding, :r13
            field :challenge_tail, :r12
        end

        class Authenticate < Packet
            field :client_flags, :l32
            field :max_packet_size, :l32, 0x1000000
            field :charset_number, :l8
            field :filler, :r23, ("\x00" * 23).extend(StringX)
            field :name, :asciiz
            field :response, :lcstring
            field :database, :asciiz
        end

        class OK < Packet
            field :field_count, :lcb_int
            field :affected_rows, :lcb_int
            field :insert_id, :lcb_int
            field :server_status, :l16
            field :warning_count, :l16
            field :message, :asciiz
        end

        class Error < Packet
            field :field_count, :l8
            field :errno, :l16
            field :sqlstate_market, :l8
            field :sqlstate, :r5
            field :message, :asciiz
        end

        class ResultSet < Packet
            field :field_count, :lcb_int
            field :extra, :lcb_int
        end

        class Field < Packet
            field :catalog, :lcstring
            field :db, :lcstring
            field :table, :lcstring
            field :org_table, :lcstring
            field :name, :lcstring
            field :org_name, :lcstring
            field :zero, :l8
            field :charsetnr, :l16
            field :length, :l32
            field :type, :l8
            field :flags, :l16
            field :decimals, :l8
            field :z2, :l16
            field :default, :lcstring
        end

        class EOF < Packet
            field :field_count, :l8
            field :warning_count, :l16
            field :status_flags, :l16
        end

        class RowData < Packet
        end

        class ChangeUser < Packet
            field :command, :l8, Commands::CHANGE_USER
            field :name, :asciiz
            field :password, :lcstring
            field :database, :asciiz
            field :charset, :l16, 0x8
        end

        class ProcessKill < Packet
            field :command, :l8, Commands::PROCESS_KILL
            field :process, :l32
        end

        class Command < Packet
            field :command, :l8
            field :arg, :asciiz
        end

        class PrepareStatement < Packet
            field :command, :l8, Commands::STMT_PREPARE
            field :query, :asciiz
        end

        class PrepareOk < Packet
            field :field_count, :l8
            field :stmt_id, :l32
            field :columns, :l16
            field :parameters, :l16
        end
    end

end

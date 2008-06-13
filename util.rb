# XXX monkeying with Numeric, shameful.

class Numeric
    def to_lcb_int
        case self
        when 0..250
            self.chr
        when 251..0xFFFF
            "\xfc" + self.to_l16
        when 0x10000..0xFFFFFFFF
            "\xfd" + self.to_l32
        else
            "\xfe" + self.to_l64
        end
    end

    def to_l8; self.chr; end
    def to_l32; [self].pack("L"); end
    def to_l16; [self].pack("v"); end
    def to_l64; [self].pack("Q"); end
    def to_l24; self.to_l32[0,3]; end

    def ord; self; end unless RUBY_VERSION[0..2] == '1.9'
end

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
    module ModuleX
        def to_name_hash
            @name_hash ||= constants.map {|k| [k.intern, const_get(k.intern)]}.to_hash
        end

        def to_key_hash
            @key_hash ||= constants.map {|k| [const_get(k.intern), k.intern]}.to_hash
        end
    end

    module StringX
        def crypt(nonce)
            sha = lambda {|k| OpenSSL::Digest::SHA1.new(k).digest }
            h3 = sha.call(nonce + sha.call((h1 = sha.call(self))))
            (0...h3.size).map {|i| (h3[i].ord ^ h1[i].ord).chr }.join("").extend(StringX)
        end

        def to_lcb_int(sz=false)
            s = 1
            case (r = self.to_l8())
            when 0..250
                r
            when 251
                r = :null
            when 252
                r = self[1..2].extend(StringX).to_l16
                s = 3
            when 253
                r = self[1..4].extend(StringX).to_l32
                s = 5
            when 254
                r = self[1..8].extend(StringX).to_l64
                s = 9
            else
                raise "invalid discriminator"
            end

            if sz
                return r, sz
            else
                return r
            end
        end

        def to_l8; unpack("C").first; end
        def to_l16; unpack("v").first; end
        def to_l32; unpack("L").first; end
        def to_l64; unpack("Q").first; end ## XXX endian
        def to_l24; (self[0,3] + "\x00").unpack("L").first; end # XXX cheat

        def shift_lcb_int
            case (x = shift_l8())
            when 0..250
                x
            when 251
                :null
            when 252
                shift_l16()
            when 253
                shift_l32()
            when 254
                shift_l64()
            else
                raise "invalid discriminator"
            end
        end

        def shift_l8; slice!(0..0).extend(StringX).to_l8; end
        def shift_l16; slice!(0...2).extend(StringX).to_l16; end
        def shift_l24; slice!(0...3).extend(StringX).to_l24; end
        def shift_l32; slice!(0...4).extend(StringX).to_l32; end
        def shift_l64; slice!(0...8).extend(StringX).to_l64; end

        def to_asciiz
            if(i = index "\x00")
                self[0,i-1]
            else
                self
            end
        end

        def shift_asciiz
            if(i = index "\x00")
                slice!(0..i)[0..-2]
            else
                slice!(0,size)
            end
        end

        def shift_r(sz)
            slice!(0, sz)
        end

        def to_lcstring
            return "" if self.size == 0
            len, lenlen = self.to_lcb_int
            return "" if len == 0
            return self[lenlen,len]
        end

        def shift_lcstring
            return "" if self.size == 0
            len = self.shift_lcb_int
            return "" if len == 0
            slice!(0,len)
        end

        def to_lcstring
            size.to_lcb_int + self
        end

        def to_asciiz
            return "" if self == ""
            self + "\x00" # XXX cheating
        end

        def to_r; self; end
    end
end



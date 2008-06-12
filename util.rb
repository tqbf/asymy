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
end

module Asymy
    module StringX
        def crypt(nonce)
            sha = lambda {|k| OpenSSL::Digest::SHA1.new(k).digest }
            h3 = sha.call(nonce + sha.call((h1 = sha.call(self))))
            (0...h3.size).map {|i| (h3[i] ^ h1[i]).chr }.join("").extend(StringX)
        end

        def to_lcb_int(sz=false)
            s = 1
            case self[0]
            when 0..250
                r = self[0]
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

        def to_l16; unpack("v").first; end
        def to_l32; unpack("L").first; end
        def to_l64; unpack("Q").first; end ## XXX endian
        def to_l24; (self[0,3] + "\x00").unpack("L").first; end # XXX cheat

        def shift_lcb_int
            case (x = slice!(0))
            when 0..250
                x
            when 251
                :null
            when 252
                slice!(0..2).extend(StringX).to_l16
            when 253
                slice!(0..4).extend(StringX).to_l32
            when 254
                slice!(0..8).extend(StringX).to_l64
            else
                raise "invalid discriminator"
            end
        end

        def shift_l8; slice!(0); end
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



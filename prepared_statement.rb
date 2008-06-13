require File.dirname(__FILE__) + '/asymy'

module Asymy

    class PreparedStatement
        def initialize(opts={})
            @bp = opts[:backpointer]
            @handle = opts[:handle]
        end

        def exec(*args, &block)
            @bp.execute_prepared(args) {|cols, rows| block.call(cals, rows)}
        end
    end
end

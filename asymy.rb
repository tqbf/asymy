%w[util
   constants
   messages
   prepared_statement
   connection].each {|f| require "#{ File.dirname(__FILE__) }/#{ f }" }

require 'stringio'


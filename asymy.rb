%w[util
   constants
   messages
   connection].each {|f| require "#{ File.dirname(__FILE__) }/#{ f }" }



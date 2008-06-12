#!/usr/bin/env ruby

require 'rubygems'
require 'eventmachine'
require 'pp'
require 'asymy'

EventMachine::run {
    c = Asymy::Connection.new(:target => "localhost",
                              :port => 13306,
                              :username => "clockwork",
                              :password => "clockwork",
                              :database => "mysql")
    c.exec("select * from user") do |x, y|
        pp x
        pp y
    end
}

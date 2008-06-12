#!/usr/bin/env ruby

require 'rubygems'
require 'eventmachine'
require 'pp'
require 'asymy'

EventMachine::run {
    c = Asymy::Connection.new(:target => "localhost",
                              :port => 13306,
                              :username => "user",
                              :password => "pass",
                              :database => "mysql")
    c.exec("select * from user") do |x, y|
        pp x
        pp y
    end
}

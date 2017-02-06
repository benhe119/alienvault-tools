#!/usr/bin/env python
# encoding: utf-8
"""
alienvault_plugin_debugger.py

Created by lhan on 2016-05-20.
Copyright (c) 2016 Xetus. All rights reserved.
"""

import sys, os
import getopt
import re


help_message = '''
A helper tool to analysis an alienvault datasource plugin(e.g. ossec-single-line.cfg) with any given logs. 
Telling a single or multiply log entry matched to which event(s); Lower id will get higher priority

Example:
  python alienvault_plugin_debugger.py  -p [PATH_TO_PLUGIN] -l [PATH_TO_LOG]
'''
events = []
logs = []

class Usage(Exception):
  def __init__(self, msg):
    self.msg = msg

class Event():
  
  def __init__(self, configs):
    self.id = configs[0][1:5]
    self.name = configs[0][8:-2]
    for configLine in configs[1:]:
      if configLine[0] != '#':
        key,value = configLine.split('=',1)
        if key and value:
          
          self.__dict__[key] = value.strip('\n')
          if key == 'regexp':
            regexp = self.__dict__[key]
            # only trim " for regexp
            if regexp[0] == '"' and regexp[-1] == '"':
              self.regexp= regexp[1:-1]

  def __str__(self):
      sb = []
      for key in self.__dict__:
          sb.append("{key}='{value}'".format(key=key, value=self.__dict__[key]))

      return ', '.join(sb)

  def __repr__(self):
      return self.__str__() 

def loadEvents(scriptFile):
  eventConfig = []
  isEventConfig = False
  for line in scriptFile:
    if line.startswith('[') and line[1].isdigit():
      eventConfig = []
      isEventConfig = True
    if isEventConfig and line == "\n":
      isEventConfig = False
      events.append(Event(eventConfig))
    if isEventConfig:
      eventConfig.append(line)
  if isEventConfig:
    events.append(Event(eventConfig))
    


def main(argv=None):
  if argv is None:
    argv = sys.argv
  try:
    try:
      opts, args = getopt.getopt(argv[1:], "hp:vl:", ["help", "plugin=", "log="])
    except getopt.error, msg:
      raise Usage(msg)
  
    # option processing
    for option, value in opts:
      if option == "-v":
        verbose = True
      if option in ("-h", "--help"):
        raise Usage(help_message)
      if option in ("-p", "--plugin"):
        pluginPath = value
        if os.path.isfile(pluginPath):
          with open(pluginPath, 'r') as script:
            loadEvents(script)
      if option in ("-l", "--log"):
        if os.path.isfile(value):
          with open(value, 'r') as logFile:
            for line in logFile:
              logs.append(line)
        else:
          logs.append(value)
    for log in logs:
      
      print "\n\nMatching log:\n\t%s" % (log)
      for event in events:
        match = re.search(event.regexp, log)
        if match is not None:
          print "\nEvent matched %s - %s:\n\t%s" % (event.id, event.name, event)
          print "\nParsed:\n\t%s" % (match.groupdict())
    
  except Usage, err:
    print >> sys.stderr, sys.argv[0].split("/")[-1] + ": " + str(err.msg)
    print >> sys.stderr, "\t for help use --help"
    return 2


if __name__ == "__main__":
  sys.exit(main())

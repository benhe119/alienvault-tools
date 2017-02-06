## Tools

### Plugin debugger tool

A helper tool to analysis an alienvault datasource plugin(e.g. ossec-single-line.cfg) with any given logs. Telling a single or multiply log entry matched to which event(s); Lower id will get higher priority.

Example:
```
  python alienvault_plugin_debugger.py  -p [PATH_TO_PLUGIN] -l [PATH_TO_LOG] 
```


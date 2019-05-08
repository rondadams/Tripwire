SYNOPSIS

  Update Tripwire Enterprise Node Descriptions with the latest version info using API.

DESCRIPTION

  This script will:
  1) Prompt for TE user credentials
  2) Connect to the TE Console API
  3) Query node(s) for the specified name and tag set (optional)
  4) Fetch list of nodes and properties
  5) Update (replace) the description with new version info contained in Make, Model, Version fields.
  
NOTE: Use caution when updating for multiple or a tag set, as all nodes selected will be updated. 
